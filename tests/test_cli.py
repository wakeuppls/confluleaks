import unittest
from contextlib import redirect_stdout
from io import StringIO

import confluleaks
import scanner
from scanner.main import build_parser


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


if __name__ == "__main__":
    unittest.main()
