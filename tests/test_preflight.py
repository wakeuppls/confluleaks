import io
import json
import unittest

from scanner.confluence import ConfluenceError
from scanner.preflight import (
    PreflightChecker,
    write_json_preflight,
    write_text_preflight,
)


class HealthyPreflightClient:
    def get_spaces(self, limit=None):
        return {"results": [{"key": "ENG"}]}

    def get_space(self, space_key):
        return {"key": space_key}

    def get_pages(self, limit=None, space_key=None):
        return {
            "results": [
                {
                    "id": "10",
                    "space": {"key": space_key},
                    "version": {"number": 3},
                    "body": {
                        "storage": {
                            "value": "<p>synthetic source body</p>",
                        }
                    },
                }
            ]
        }

    def get_comments(self, page_id, limit=None):
        return {
            "results": [
                {
                    "id": "comment-1",
                    "body": {"storage": {"value": "synthetic comment body"}},
                }
            ]
        }

    def get_attachments(self, page_id, limit=None):
        return {"results": [{"id": "attachment-1"}]}

    def get_page_version(self, page_id, version):
        return {
            "id": page_id,
            "version": {"number": version},
            "body": {"storage": {"value": "synthetic historical body"}},
        }


class PreflightTest(unittest.TestCase):
    def test_requested_capabilities_pass_on_rest_v1_shape(self):
        result = PreflightChecker(
            HealthyPreflightClient(),
            space_keys=["ENG"],
            check_history=True,
            check_comments=True,
            check_attachments=True,
        ).run()

        self.assertTrue(result.ok)
        self.assertEqual(
            [check.name for check in result.checks],
            [
                "rest_api",
                "space:ENG",
                "pages:ENG",
                "comments:ENG",
                "attachments:ENG",
                "history:ENG",
            ],
        )
        self.assertTrue(all(check.status == "pass" for check in result.checks))

    def test_authentication_failure_stops_without_exposing_response_body(self):
        class UnauthorizedClient(HealthyPreflightClient):
            def get_spaces(self, limit=None):
                raise ConfluenceError(
                    "request failed without response body",
                    status_code=401,
                )

        result = PreflightChecker(UnauthorizedClient()).run()

        self.assertFalse(result.ok)
        self.assertEqual(len(result.checks), 1)
        self.assertEqual(result.checks[0].status, "fail")
        self.assertEqual(
            result.checks[0].message,
            "authentication was rejected by Confluence (HTTP 401)",
        )

    def test_unavailable_previous_version_is_a_warning(self):
        class MissingHistoryClient(HealthyPreflightClient):
            def get_page_version(self, page_id, version):
                raise ConfluenceError("not found", status_code=404)

        result = PreflightChecker(
            MissingHistoryClient(),
            check_history=True,
        ).run()

        self.assertTrue(result.ok)
        history = next(check for check in result.checks if check.name == "history:ENG")
        self.assertEqual(history.status, "warn")

    def test_invalid_page_shape_fails_compatibility_check(self):
        class InvalidPageClient(HealthyPreflightClient):
            def get_pages(self, limit=None, space_key=None):
                return {"results": [{"id": "10"}]}

        result = PreflightChecker(InvalidPageClient()).run()

        self.assertFalse(result.ok)
        self.assertEqual(result.checks[-1].name, "pages:ENG")
        self.assertEqual(result.checks[-1].status, "fail")

    def test_requested_space_must_match_direct_lookup_response(self):
        client = HealthyPreflightClient()
        client.get_space = lambda space_key: {"key": "OTHER"}

        result = PreflightChecker(client, space_keys=["ENG"]).run()

        self.assertFalse(result.ok)
        self.assertEqual(result.checks[-1].name, "space:ENG")
        self.assertEqual(result.checks[-1].status, "fail")

    def test_reports_are_machine_readable_and_source_safe(self):
        result = PreflightChecker(
            HealthyPreflightClient(),
            check_comments=True,
            check_history=True,
        ).run()
        text_output = io.StringIO()
        json_output = io.StringIO()

        write_text_preflight(result, text_output)
        write_json_preflight(result, json_output)
        payload = json.loads(json_output.getvalue())
        combined = text_output.getvalue() + json_output.getvalue()

        self.assertTrue(payload["preflight"]["ok"])
        self.assertIn("Confluleaks preflight: PASS", text_output.getvalue())
        self.assertNotIn("synthetic source body", combined)
        self.assertNotIn("synthetic comment body", combined)
        self.assertNotIn("synthetic historical body", combined)


if __name__ == "__main__":
    unittest.main()
