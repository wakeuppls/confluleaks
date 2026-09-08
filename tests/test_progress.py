import io
import unittest

from scanner.progress import ProgressReporter


class ProgressReporterTest(unittest.TestCase):
    def test_writes_elapsed_line_and_flushes(self):
        ticks = iter((10.0, 11.0, 3_671.0))
        output = io.StringIO()
        reporter = ProgressReporter(output, clock=lambda: next(ticks))

        reporter("Starting scan")
        reporter("Scan complete")

        self.assertEqual(
            output.getvalue(),
            "[confluleaks +00:00:01] Starting scan\n"
            "[confluleaks +01:01:01] Scan complete\n",
        )

    def test_broken_progress_stream_does_not_break_the_scan(self):
        class BrokenStream:
            def __init__(self):
                self.writes = 0

            def write(self, value):
                self.writes += 1
                raise BrokenPipeError

            def flush(self):
                raise AssertionError("flush must not run after a failed write")

        stream = BrokenStream()
        reporter = ProgressReporter(stream, clock=lambda: 0.0)

        reporter("First message")
        reporter("Second message")

        self.assertEqual(stream.writes, 1)


if __name__ == "__main__":
    unittest.main()
