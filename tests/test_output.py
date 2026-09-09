import os
import stat
import tempfile
import unittest
from io import StringIO
from pathlib import Path

from scanner.output import ReportOutputError, write_report_output


class ReportOutputTest(unittest.TestCase):
    def test_defaults_to_stdout(self):
        output = StringIO()

        write_report_output(None, lambda stream: stream.write("report\n"), output)

        self.assertEqual(output.getvalue(), "report\n")

    def test_atomically_writes_private_file_and_creates_parents(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "report.json"

            write_report_output(
                path,
                lambda stream: stream.write('{"ok": true}\n'),
            )

            self.assertEqual(path.read_text(encoding="utf-8"), '{"ok": true}\n')
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(list(path.parent.glob(f".{path.name}.*.tmp")), [])

    def test_failed_write_preserves_existing_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text("previous\n", encoding="utf-8")

            def fail_after_partial_write(stream):
                stream.write("partial")
                raise OSError("synthetic write failure")

            with self.assertRaises(ReportOutputError):
                write_report_output(path, fail_after_partial_write)

            self.assertEqual(path.read_text(encoding="utf-8"), "previous\n")
            self.assertEqual(list(path.parent.glob(f".{path.name}.*.tmp")), [])

    def test_replaces_existing_permissions_with_private_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.txt"
            path.write_text("old", encoding="utf-8")
            os.chmod(path, 0o644)

            write_report_output(path, lambda stream: stream.write("new\n"))

            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
