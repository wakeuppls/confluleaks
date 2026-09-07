import json
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from unittest.mock import MagicMock, Mock, patch

import confluleaks
import scanner
from scanner.auth import AuthConfigurationError, AuthMethod
from scanner.main import _load_auth, build_parser, main
from scanner.models import ScanResult
from scanner.preflight import PreflightResult


class PublicCliTest(unittest.TestCase):
    def test_public_command_uses_product_name(self):
        self.assertEqual(build_parser().prog, "confluleaks")

    def test_public_module_exports_the_scanner_version(self):
        self.assertEqual(confluleaks.__version__, scanner.__version__)
        self.assertRegex(confluleaks.__version__, r"^\d+\.\d+\.\d+$")

    def test_version_flag_uses_public_product_name(self):
        output = StringIO()

        with redirect_stdout(output), self.assertRaises(SystemExit) as exit_error:
            build_parser().parse_args(["--version"])

        self.assertEqual(exit_error.exception.code, 0)
        self.assertEqual(output.getvalue(), "confluleaks 0.1.0\n")

    def test_comments_flag_is_opt_in(self):
        parser = build_parser()

        self.assertFalse(parser.parse_args([]).comments)
        self.assertTrue(parser.parse_args(["--comments"]).comments)

    def test_auth_defaults_to_bearer_and_honors_environment_default(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(build_parser().parse_args([]).auth, "bearer")
        with patch.dict(os.environ, {"CONFLUENCE_AUTH": "BASIC"}, clear=True):
            self.assertEqual(build_parser().parse_args([]).auth, "basic")

    def test_auth_is_loaded_from_environment(self):
        with patch.dict(
            os.environ,
            {"CONFLUENCE_TOKEN": "bearer-secret"},
            clear=True,
        ):
            bearer = _load_auth("bearer")
        with patch.dict(
            os.environ,
            {
                "CONFLUENCE_TOKEN": "basic-secret",
                "CONFLUENCE_USERNAME": "scanner@example.test",
            },
            clear=True,
        ):
            basic = _load_auth("basic")

        self.assertEqual(bearer.method, AuthMethod.BEARER)
        self.assertEqual(basic.method, AuthMethod.BASIC)
        self.assertEqual(basic.username, "scanner@example.test")

    def test_basic_auth_requires_username(self):
        with patch.dict(
            os.environ,
            {"CONFLUENCE_TOKEN": "basic-secret"},
            clear=True,
        ), self.assertRaises(AuthConfigurationError):
            _load_auth("basic")

    def test_all_auth_methods_require_token(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(AuthConfigurationError):
                _load_auth("bearer")
            with self.assertRaises(AuthConfigurationError):
                _load_auth("basic")

    def test_large_installation_guardrail_defaults(self):
        args = build_parser().parse_args([])

        self.assertEqual(args.max_response_size_mb, 16.0)
        self.assertEqual(args.max_document_size_mb, 5.0)
        self.assertEqual(args.regex_timeout, 0.25)
        self.assertEqual(args.max_findings, 10_000)
        self.assertEqual(args.max_findings_per_document, 1_000)
        self.assertEqual(args.max_runtime, 3_600.0)

    def test_preflight_bypasses_rules_and_returns_its_status(self):
        result = PreflightResult()
        result.add("rest_api", "pass", "synthetic success")
        checker = Mock()
        checker.run.return_value = result
        client = MagicMock()
        client.__enter__.return_value = client
        output = StringIO()

        with patch.dict(
            os.environ,
            {"CONFLUENCE_TOKEN": "synthetic-token"},
            clear=True,
        ), patch("scanner.main.ConfluenceClient", return_value=client), patch(
            "scanner.main.PreflightChecker", return_value=checker
        ) as checker_class, patch(
            "scanner.main.load_rules"
        ) as load_rules, redirect_stdout(output):
            exit_code = main(
                [
                    "--no-config",
                    "--url",
                    "https://confluence.example.test",
                    "--preflight",
                    "--space",
                    "ENG",
                    "--comments",
                    "--baseline",
                    "ignored-during-preflight.json",
                    "--fail-on",
                    "high",
                    "--format",
                    "json",
                ]
            )

        self.assertEqual(exit_code, 0)
        self.assertTrue(json.loads(output.getvalue())["preflight"]["ok"])
        load_rules.assert_not_called()
        self.assertEqual(checker_class.call_args.kwargs["space_keys"], ["ENG"])
        self.assertTrue(checker_class.call_args.kwargs["check_comments"])

    def test_preflight_rejects_sarif_output(self):
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as error:
            main(
                [
                    "--no-config",
                    "--url",
                    "https://confluence.example.test",
                    "--preflight",
                    "--format",
                    "sarif",
                ]
            )

        self.assertEqual(error.exception.code, 2)

    def test_truncated_result_returns_operational_error(self):
        result = ScanResult()
        result.mark_truncated("max_pages")
        scanner = Mock()
        scanner.scan.return_value = result
        client = MagicMock()
        client.__enter__.return_value = client

        with patch.dict(
            os.environ,
            {"CONFLUENCE_TOKEN": "synthetic-token"},
            clear=True,
        ), patch("scanner.main.load_rules", return_value=[]), patch(
            "scanner.main.ConfluenceClient", return_value=client
        ), patch("scanner.main.SecretScanner", return_value=scanner), redirect_stdout(
            StringIO()
        ):
            exit_code = main(
                ["--no-config", "--url", "https://confluence.example.test"]
            )

        self.assertEqual(exit_code, 1)


if __name__ == "__main__":
    unittest.main()
