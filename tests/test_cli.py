import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import confluleaks
import scanner
from scanner.auth import AuthConfigurationError, AuthMethod
from scanner.main import (
    _confirm_insecure_http,
    _load_auth,
    _safe_url_for_log,
    _validate_arguments,
    build_parser,
    main,
)
from scanner.models import ScanResult
from scanner.preflight import PreflightResult


class TtyInput(StringIO):
    def isatty(self):
        return True


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

    def test_show_secrets_is_explicit_and_can_override_config(self):
        self.assertFalse(build_parser().parse_args([]).show_secrets)
        self.assertTrue(build_parser().parse_args(["--show-secrets"]).show_secrets)
        self.assertFalse(
            build_parser({"show_secrets": True})
            .parse_args(["--no-show-secrets"])
            .show_secrets
        )

    def test_progress_can_be_forced_or_disabled(self):
        parser = build_parser({"progress": True})

        self.assertTrue(parser.parse_args([]).progress)
        self.assertFalse(parser.parse_args(["--no-progress"]).progress)

    def test_https_does_not_require_transport_confirmation(self):
        output = StringIO()

        approved = _confirm_insecure_http(
            "https://confluence.example.test",
            False,
            input_stream=TtyInput("n\n"),
            output_stream=output,
        )

        self.assertTrue(approved)
        self.assertEqual(output.getvalue(), "")

    def test_interactive_http_requires_explicit_yes(self):
        answers = (
            ("y\n", True),
            ("YES\n", True),
            ("n\n", False),
            ("\n", False),
            ("", False),
        )
        for answer, expected in answers:
            with self.subTest(answer=answer):
                output = StringIO()
                approved = _confirm_insecure_http(
                    "http://confluence.example.test",
                    False,
                    input_stream=TtyInput(answer),
                    output_stream=output,
                )

                self.assertEqual(approved, expected)
                self.assertIn("unencrypted HTTP", output.getvalue())
                self.assertIn("[y/N]", output.getvalue())

    def test_noninteractive_http_fails_closed_without_override(self):
        output = StringIO()

        approved = _confirm_insecure_http(
            "http://confluence.example.test",
            False,
            input_stream=StringIO("y\n"),
            output_stream=output,
        )

        self.assertFalse(approved)
        self.assertIn("--allow-insecure-http", output.getvalue())

    def test_insecure_http_override_does_not_read_stdin(self):
        output = StringIO()

        approved = _confirm_insecure_http(
            "http://127.0.0.1:8765",
            True,
            input_stream=StringIO(),
            output_stream=output,
        )

        self.assertTrue(approved)
        self.assertIn("continuing", output.getvalue())

    def test_declined_http_stops_before_authentication(self):
        with patch("sys.stdin", TtyInput("n\n")), patch(
            "scanner.main.ConfluenceClient"
        ) as client_class, redirect_stderr(StringIO()):
            exit_code = main(
                ["--no-config", "--url", "http://confluence.example.test"]
            )

        self.assertEqual(exit_code, 1)
        client_class.assert_not_called()

    def test_insecure_http_warning_does_not_corrupt_json(self):
        result = PreflightResult()
        result.add("authentication", "pass", "synthetic success")
        checker = Mock()
        checker.run.return_value = result
        client = MagicMock()
        client.__enter__.return_value = client
        stdout = StringIO()
        stderr = StringIO()

        with patch.dict(
            os.environ,
            {"CONFLUENCE_TOKEN": "synthetic-token"},
            clear=True,
        ), patch(
            "scanner.main.ConfluenceClient",
            return_value=client,
        ), patch(
            "scanner.main.PreflightChecker",
            return_value=checker,
        ), redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = main(
                [
                    "--no-config",
                    "--url",
                    "http://confluence.example.test",
                    "--allow-insecure-http",
                    "--preflight",
                    "--format",
                    "json",
                ]
            )

        self.assertEqual(exit_code, 0)
        self.assertTrue(json.loads(stdout.getvalue())["preflight"]["ok"])
        self.assertIn("unencrypted HTTP", stderr.getvalue())
        self.assertNotIn("warning", stdout.getvalue())

    def test_preflight_can_write_json_report_to_file(self):
        result = PreflightResult()
        result.add("authentication", "pass", "synthetic success")
        checker = Mock()
        checker.run.return_value = result
        client = MagicMock()
        client.__enter__.return_value = client
        stdout = StringIO()

        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "nested" / "preflight.json"
            with patch.dict(
                os.environ,
                {"CONFLUENCE_TOKEN": "synthetic-token"},
                clear=True,
            ), patch(
                "scanner.main.ConfluenceClient",
                return_value=client,
            ), patch(
                "scanner.main.PreflightChecker",
                return_value=checker,
            ), redirect_stdout(stdout):
                exit_code = main(
                    [
                        "--no-config",
                        "--url",
                        "https://confluence.example.test",
                        "--preflight",
                        "--format",
                        "json",
                        "--output",
                        str(output_path),
                    ]
                )

            payload = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertTrue(payload["preflight"]["ok"])
        self.assertEqual(stdout.getvalue(), "")

    def test_output_cannot_overwrite_a_scanner_input(self):
        parser = build_parser()
        path = Path("same-file.yaml")
        args = parser.parse_args(["--rules", str(path), "--output", str(path)])

        with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as error:
            _validate_arguments(parser, args)

        self.assertEqual(error.exception.code, 2)

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

    def test_non_finite_cli_numbers_are_rejected(self):
        invalid_options = (
            ("--timeout", "nan"),
            ("--backoff", "nan"),
            ("--request-delay", "inf"),
        )
        for option, value in invalid_options:
            with self.subTest(option=option), redirect_stderr(
                StringIO()
            ), self.assertRaises(SystemExit) as error:
                main(
                    [
                        "--no-config",
                        "--url",
                        "https://confluence.example.test",
                        option,
                        value,
                    ]
                )
            self.assertEqual(error.exception.code, 2)

    def test_explicit_no_history_overrides_configured_history_limit(self):
        parser = build_parser({"history_limit": 5})
        args = parser.parse_args(["--no-history"])

        _validate_arguments(parser, args)

        self.assertFalse(args.history)
        self.assertIsNone(args.history_limit)

    def test_empty_space_key_is_rejected(self):
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as error:
            build_parser().parse_args(["--space", "   "])

        self.assertEqual(error.exception.code, 2)

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
        ), patch(
            "scanner.main.ConfluenceClient",
            return_value=client,
        ) as client_class, patch(
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
                    "--ca-bundle",
                    "/tmp/synthetic-company-ca.pem",
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
        self.assertEqual(
            client_class.call_args.kwargs["ca_bundle"],
            Path("/tmp/synthetic-company-ca.pem"),
        )
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

    def test_progress_uses_stderr_without_corrupting_json(self):
        result = PreflightResult()
        result.add("authentication", "pass", "synthetic success")
        checker = Mock()
        checker.run.return_value = result
        client = MagicMock()
        client.__enter__.return_value = client
        stdout = StringIO()
        stderr = StringIO()

        with patch.dict(
            os.environ,
            {"CONFLUENCE_TOKEN": "synthetic-token"},
            clear=True,
        ), patch(
            "scanner.main.ConfluenceClient",
            return_value=client,
        ), patch(
            "scanner.main.PreflightChecker",
            return_value=checker,
        ), redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = main(
                [
                    "--no-config",
                    "--url",
                    "https://confluence.example.test",
                    "--preflight",
                    "--progress",
                    "--format",
                    "json",
                ]
            )

        self.assertEqual(exit_code, 0)
        self.assertTrue(json.loads(stdout.getvalue())["preflight"]["ok"])
        self.assertIn("Starting preflight", stderr.getvalue())
        self.assertIn("Preflight passed", stderr.getvalue())
        self.assertNotIn("[confluleaks", stdout.getvalue())

    def test_diagnostic_log_records_run_without_credentials(self):
        result = PreflightResult()
        result.add("authentication", "pass", "synthetic success")
        checker = Mock()
        checker.run.return_value = result
        client = MagicMock()
        client.__enter__.return_value = client

        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "confluleaks.log"
            with patch.dict(
                os.environ,
                {"CONFLUENCE_TOKEN": "synthetic-secret-token"},
                clear=True,
            ), patch(
                "scanner.main.ConfluenceClient",
                return_value=client,
            ), patch(
                "scanner.main.PreflightChecker",
                return_value=checker,
            ), redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                exit_code = main(
                    [
                        "--no-config",
                        "--url",
                        "https://confluence.example.test",
                        "--preflight",
                        "--log-file",
                        str(log_path),
                        "--log-level",
                        "debug",
                        "--format",
                        "json",
                    ]
                )

            log_content = log_path.read_text(encoding="utf-8")

        self.assertEqual(exit_code, 0)
        self.assertIn('"event": "run.started"', log_content)
        self.assertIn('"event": "run.finished"', log_content)
        self.assertNotIn("synthetic-secret-token", log_content)
        self.assertNotIn("CONFLUENCE_TOKEN", log_content)

    def test_diagnostic_log_redacts_credentials_embedded_in_url(self):
        unsafe_url = "https://alice:secret@confluence.example.test"

        self.assertEqual(_safe_url_for_log(unsafe_url), "<credentials-redacted>")

    def test_show_secrets_is_forwarded_to_detection_and_report(self):
        result = ScanResult()
        scanner = Mock()
        scanner.scan.return_value = result
        client = MagicMock()
        client.__enter__.return_value = client
        stderr = StringIO()

        with patch.dict(
            os.environ,
            {"CONFLUENCE_TOKEN": "synthetic-token"},
            clear=True,
        ), patch("scanner.main.load_rules", return_value=[]), patch(
            "scanner.main.ConfluenceClient",
            return_value=client,
        ), patch("scanner.main.Detector") as detector_class, patch(
            "scanner.main.SecretScanner",
            return_value=scanner,
        ), patch("scanner.main.write_json_report") as writer, redirect_stdout(
            StringIO()
        ), redirect_stderr(stderr):
            exit_code = main(
                [
                    "--no-config",
                    "--url",
                    "https://confluence.example.test",
                    "--show-secrets",
                    "--format",
                    "json",
                ]
            )

        self.assertEqual(exit_code, 0)
        self.assertTrue(detector_class.call_args.kwargs["show_secrets"])
        self.assertTrue(writer.call_args.kwargs["show_secrets"])
        self.assertIn("writes plaintext secrets", stderr.getvalue())

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
