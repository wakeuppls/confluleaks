import io
import json
import re
import unittest

from scanner.detector import Detector
from scanner.confluence import ConfluenceError
from scanner.models import Rule, Severity
from scanner.report import write_json_report, write_text_report
from scanner.service import SecretScanner


class FakeConfluenceClient:
    base_url = "https://confluence.example.test"

    def iter_spaces(self):
        yield {"key": "ENG", "name": "Engineering"}

    def iter_pages(self, space_key=None):
        yield {
            "id": "10",
            "title": "Deployment",
            "space": {"key": "ENG"},
            "version": {"number": 4},
            "body": {"storage": {"value": "<p>password=secret-value</p>"}},
            "_links": {"webui": "/spaces/ENG/pages/10"},
        }

    def absolute_url(self, relative_url):
        return f"{self.base_url}{relative_url}"

    def iter_page_history(self, page_id, current_version, limit=None):
        versions = [
            {
                "id": "10",
                "title": "Deployment",
                "space": {"key": "ENG"},
                "version": {"number": 3},
                "body": {"storage": {"value": "<p>password=secret-value</p>"}},
                "_links": {"webui": "/spaces/ENG/pages/10"},
            },
            {
                "id": "10",
                "title": "Deployment",
                "space": {"key": "ENG"},
                "version": {"number": 2},
                "body": {"storage": {"value": "<p>password=old-secret</p>"}},
                "_links": {"webui": "/spaces/ENG/pages/10"},
            },
            {
                "id": "10",
                "title": "Deployment",
                "space": {"key": "ENG"},
                "version": {"number": 1},
                "body": {"storage": {"value": "<p>clean</p>"}},
                "_links": {"webui": "/spaces/ENG/pages/10"},
            },
        ]
        yield from versions[:limit]


class ServiceAndReportTest(unittest.TestCase):
    def setUp(self):
        regex = r"password=(?P<secret>\S+)"
        rule = Rule(
            id="password",
            name="Password",
            severity=Severity.HIGH,
            regex=regex,
            pattern=re.compile(regex),
            confidence=0.9,
        )
        self.result = SecretScanner(
            FakeConfluenceClient(), Detector([rule])
        ).scan()

    def test_scans_pages_and_spaces(self):
        self.assertEqual(self.result.spaces_scanned, 1)
        self.assertEqual(self.result.pages_scanned, 1)
        self.assertEqual(len(self.result.findings), 1)
        self.assertEqual(self.result.findings[0].page_url, "https://confluence.example.test/spaces/ENG/pages/10")

    def test_text_report_never_contains_secret(self):
        output = io.StringIO()

        write_text_report(self.result, output)

        self.assertIn("[HIGH] Password", output.getvalue())
        self.assertNotIn("secret-value", output.getvalue())

    def test_json_report_is_machine_readable_and_secret_safe(self):
        output = io.StringIO()

        write_json_report(self.result, output)
        payload = json.loads(output.getvalue())

        self.assertEqual(
            payload["scanned"],
            {
                "spaces": 1,
                "spaces_discovered": 1,
                "pages": 1,
                "versions": 1,
                "historical_versions": 0,
                "attachments_discovered": 0,
                "attachments": 0,
                "attachments_skipped": 0,
                "attachment_bytes": 0,
            },
        )
        self.assertEqual(payload["finding_counts"]["high"], 1)
        self.assertEqual(payload["baseline"], {"suppressed_findings": 0})
        self.assertFalse(payload["truncated"])
        self.assertEqual(payload["errors"], [])
        self.assertNotIn("secret-value", output.getvalue())

    def test_history_is_scanned_and_duplicate_findings_are_collapsed(self):
        regex = r"password=(?P<secret>\S+)"
        rule = Rule(
            id="password",
            name="Password",
            severity=Severity.HIGH,
            regex=regex,
            pattern=re.compile(regex),
            confidence=0.9,
        )

        result = SecretScanner(
            FakeConfluenceClient(),
            Detector([rule]),
            include_history=True,
        ).scan()

        self.assertEqual(result.versions_scanned, 4)
        self.assertEqual(result.historical_versions_scanned, 3)
        self.assertEqual(len(result.findings), 2)
        self.assertEqual(result.findings[0].matched_versions, (4, 3))

    def test_history_limit_is_forwarded(self):
        result = SecretScanner(
            FakeConfluenceClient(),
            Detector([]),
            include_history=True,
            history_limit=1,
        ).scan()

        self.assertEqual(result.versions_scanned, 2)
        self.assertEqual(result.historical_versions_scanned, 1)


class ScopeFakeConfluenceClient:
    def __init__(self, broken_space=None):
        self.requested_spaces = []
        self.broken_space = broken_space

    def iter_spaces(self):
        yield {"key": "ENG", "type": "global", "status": "current"}
        yield {"key": "PUBLIC", "type": "global", "status": "current"}
        yield {"key": "OLD", "type": "global", "status": "archived"}
        yield {"key": "~bob", "type": "personal", "status": "current"}

    def iter_pages(self, space_key=None):
        self.requested_spaces.append(space_key)
        if space_key == self.broken_space:
            raise ConfluenceError("synthetic request failure", status_code=503)
        yield {
            "id": f"page-{space_key}",
            "title": space_key,
            "space": {"key": space_key},
            "version": {"number": 1},
            "body": {"storage": {"value": "<p>clean</p>"}},
        }

    def absolute_url(self, relative_url):
        return relative_url


class AttachmentFakeConfluenceClient(FakeConfluenceClient):
    def iter_attachments(self, page_id):
        yield {
            "id": "att-1",
            "title": "deployment.env",
            "metadata": {"mediaType": "text/plain"},
            "extensions": {"fileSize": 30},
        }
        yield {
            "id": "att-2",
            "title": "architecture.pdf",
            "metadata": {"mediaType": "application/pdf"},
            "extensions": {"fileSize": 100},
        }
        yield {
            "id": "att-3",
            "title": "huge.txt",
            "metadata": {"mediaType": "text/plain"},
            "extensions": {"fileSize": 10_000},
        }

    def download_attachment(self, page_id, attachment, max_bytes):
        return b"password=attachment-secret"


class AttachmentServiceTest(unittest.TestCase):
    def setUp(self):
        regex = r"password=(?P<secret>\S+)"
        self.rule = Rule(
            id="password",
            name="Password",
            severity=Severity.HIGH,
            regex=regex,
            pattern=re.compile(regex),
            confidence=0.9,
        )

    def test_attachments_are_opt_in(self):
        result = SecretScanner(
            AttachmentFakeConfluenceClient(),
            Detector([self.rule]),
        ).scan()

        self.assertEqual(result.attachments_discovered, 0)
        self.assertEqual(len(result.findings), 1)

    def test_only_supported_attachments_within_limit_are_scanned(self):
        result = SecretScanner(
            AttachmentFakeConfluenceClient(),
            Detector([self.rule]),
            include_attachments=True,
            max_attachment_bytes=100,
        ).scan()

        self.assertEqual(result.attachments_discovered, 3)
        self.assertEqual(result.attachments_scanned, 1)
        self.assertEqual(result.attachments_skipped, 2)
        self.assertEqual(result.attachment_bytes_scanned, 26)
        self.assertEqual(len(result.findings), 2)
        attachment_finding = next(
            finding for finding in result.findings if finding.attachment_id
        )
        self.assertEqual(attachment_finding.attachment_id, "att-1")
        self.assertEqual(attachment_finding.attachment_name, "deployment.env")

        text_output = io.StringIO()
        json_output = io.StringIO()
        write_text_report(result, text_output)
        write_json_report(result, json_output)
        reports = text_output.getvalue() + json_output.getvalue()
        payload = json.loads(json_output.getvalue())

        attachment_payload = next(
            finding
            for finding in payload["findings"]
            if finding["source"]["type"] == "attachment"
        )
        self.assertEqual(
            attachment_payload["source"]["attachment"],
            {"id": "att-1", "name": "deployment.env"},
        )
        self.assertIn("Attachment: deployment.env (att-1)", text_output.getvalue())
        self.assertNotIn("attachment-secret", reports)


class ScopeTest(unittest.TestCase):
    def test_personal_and_archived_spaces_are_skipped_by_default(self):
        client = ScopeFakeConfluenceClient()

        result = SecretScanner(client, Detector([])).scan()

        self.assertEqual(result.spaces_discovered, 4)
        self.assertEqual(result.spaces_scanned, 2)
        self.assertEqual(client.requested_spaces, ["ENG", "PUBLIC"])

    def test_explicit_space_overrides_personal_and_archived_defaults(self):
        client = ScopeFakeConfluenceClient()

        result = SecretScanner(
            client,
            Detector([]),
            include_spaces=["OLD", "~bob"],
        ).scan()

        self.assertEqual(result.spaces_scanned, 2)
        self.assertEqual(client.requested_spaces, ["OLD", "~bob"])

    def test_exclude_space_and_max_pages_are_applied(self):
        client = ScopeFakeConfluenceClient()

        result = SecretScanner(
            client,
            Detector([]),
            exclude_spaces=["PUBLIC"],
            include_archived_spaces=True,
            max_pages=1,
        ).scan()

        self.assertEqual(result.pages_scanned, 1)
        self.assertTrue(result.truncated)
        self.assertEqual(client.requested_spaces, ["ENG", "OLD"])

    def test_missing_requested_space_is_reported(self):
        result = SecretScanner(
            ScopeFakeConfluenceClient(),
            Detector([]),
            include_spaces=["MISSING"],
        ).scan()

        self.assertEqual(len(result.errors), 1)
        self.assertEqual(result.errors[0].scope, "space:missing")

    def test_continue_on_error_scans_remaining_spaces(self):
        client = ScopeFakeConfluenceClient(broken_space="ENG")

        result = SecretScanner(
            client,
            Detector([]),
            continue_on_error=True,
        ).scan()

        self.assertEqual(client.requested_spaces, ["ENG", "PUBLIC"])
        self.assertEqual(result.pages_scanned, 1)
        self.assertEqual(len(result.errors), 1)


if __name__ == "__main__":
    unittest.main()
