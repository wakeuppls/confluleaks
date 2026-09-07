import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import MagicMock, Mock, patch

import confluleaks
import scanner
from scanner.main import build_parser, main
from scanner.models import ScanResult


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

    def test_large_installation_guardrail_defaults(self):
        args = build_parser().parse_args([])

        self.assertEqual(args.max_response_size_mb, 16.0)
        self.assertEqual(args.max_document_size_mb, 5.0)
        self.assertEqual(args.regex_timeout, 0.25)
        self.assertEqual(args.max_findings, 10_000)
        self.assertEqual(args.max_findings_per_document, 1_000)
        self.assertEqual(args.max_runtime, 3_600.0)

    def test_truncated_result_returns_operational_error(self):
        result = ScanResult()
        result.mark_truncated("max_pages")
        scanner = Mock()
        scanner.scan.return_value = result
        client = MagicMock()
        client.__enter__.return_value = client

        with patch.dict(
            "os.environ",
            {"CONFLUENCE_TOKEN": "synthetic-token"},
        ), patch("scanner.main.load_rules", return_value=[]), patch(
            "scanner.main.ConfluenceClient", return_value=client
        ), patch("scanner.main.SecretScanner", return_value=scanner), redirect_stdout(
            StringIO()
        ):
            exit_code = main(["--url", "https://confluence.example.test"])

        self.assertEqual(exit_code, 1)


if __name__ == "__main__":
    unittest.main()
