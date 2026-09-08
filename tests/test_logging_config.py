import logging
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

try:
    import requests  # noqa: F401
except ModuleNotFoundError:
    requests = None

from scanner.logging_config import (
    DiagnosticLogError,
    diagnostic_logging,
    log_event,
)


class DiagnosticLoggingTest(unittest.TestCase):
    def test_log_is_structured_private_and_secret_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "confluleaks.log"
            with diagnostic_logging(path, "debug") as logger:
                log_event(
                    logger,
                    logging.DEBUG,
                    "synthetic.event",
                    space="ENG",
                    pages=25,
                )

            content = path.read_text(encoding="utf-8")
            mode = stat.S_IMODE(path.stat().st_mode)

        self.assertIn('"event": "diagnostic_log.started"', content)
        self.assertIn('"event": "synthetic.event"', content)
        self.assertIn('"space": "ENG"', content)
        self.assertEqual(mode & 0o077, 0)

    def test_unusable_log_path_fails_before_the_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            parent_file = Path(directory) / "not-a-directory"
            parent_file.write_text("occupied", encoding="utf-8")

            with self.assertRaises(DiagnosticLogError):
                with diagnostic_logging(parent_file / "scan.log", "debug"):
                    pass

    def test_log_rotates_at_the_configured_size(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "confluleaks.log"
            with patch("scanner.logging_config.LOG_MAX_BYTES", 256), patch(
                "scanner.logging_config.LOG_BACKUP_COUNT",
                1,
            ):
                with diagnostic_logging(path, "debug") as logger:
                    for sequence in range(20):
                        log_event(
                            logger,
                            logging.DEBUG,
                            "synthetic.event",
                            sequence=sequence,
                            padding="x" * 100,
                        )

            self.assertTrue(Path(f"{path}.1").is_file())


@unittest.skipIf(requests is None, "HTTP dependencies are not installed")
class HttpDiagnosticLoggingTest(unittest.TestCase):
    def test_http_log_has_request_metadata_but_not_credentials_or_body(self):
        from scanner.confluence import ConfluenceClient
        from tests.test_confluence_client import FakeStreamingResponse

        response = FakeStreamingResponse(b'{"results": []}')
        response.status_code = 200
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "confluleaks.log"
            with diagnostic_logging(path, "debug"):
                client = ConfluenceClient(
                    "https://confluence.example.test",
                    "synthetic-secret-token",
                )
                with patch.object(
                    client.session,
                    "get",
                    return_value=response,
                ):
                    client.get_pages(start=50, limit=25, space_key="ENG")
                client.close()

            content = path.read_text(encoding="utf-8")

        self.assertIn('"event": "http.request.started"', content)
        self.assertIn('"event": "http.request.finished"', content)
        self.assertIn("space=ENG, start=50, limit=25", content)
        self.assertIn('"response_bytes": 15', content)
        self.assertNotIn("synthetic-secret-token", content)
        self.assertNotIn("Authorization", content)
        self.assertNotIn('{"results": []}', content)


if __name__ == "__main__":
    unittest.main()
