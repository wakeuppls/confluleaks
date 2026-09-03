import unittest
from unittest.mock import patch

try:
    import requests  # noqa: F401
    import urllib3  # noqa: F401
except ModuleNotFoundError:
    requests = None


@unittest.skipIf(requests is None, "HTTP dependencies are not installed")
class ConfluenceClientConfigurationTest(unittest.TestCase):
    def test_retry_policy_covers_rate_limits_and_transient_server_errors(self):
        from scanner.confluence import ConfluenceClient

        client = ConfluenceClient(
            "https://confluence.example.test",
            "synthetic-token",
            retries=4,
            backoff=0.25,
        )
        retry = client.session.get_adapter("https://").max_retries
        client.close()

        self.assertEqual(retry.total, 4)
        self.assertEqual(retry.backoff_factor, 0.25)
        self.assertEqual(set(retry.status_forcelist), {429, 500, 502, 503, 504})
        self.assertEqual(set(retry.allowed_methods), {"GET"})
        self.assertTrue(retry.respect_retry_after_header)

    def test_request_delay_spaces_request_start_times(self):
        from scanner.confluence import ConfluenceClient

        client = ConfluenceClient(
            "https://confluence.example.test",
            "synthetic-token",
            request_delay=1.0,
        )
        with patch(
            "scanner.confluence.time.monotonic",
            side_effect=[10.0, 10.25, 11.25],
        ), patch("scanner.confluence.time.sleep") as sleep:
            client._wait_before_request()
            client._wait_before_request()
        client.close()

        sleep.assert_called_once_with(0.75)

    def test_cross_origin_attachment_link_is_rejected_before_request(self):
        from scanner.confluence import ConfluenceClient, ConfluenceError

        client = ConfluenceClient(
            "https://confluence.example.test",
            "synthetic-token",
        )
        attachment = {
            "id": "123",
            "_links": {"download": "https://attacker.example/file"},
        }

        with patch.object(client.session, "get") as request, self.assertRaises(
            ConfluenceError
        ):
            client.download_attachment("10", attachment, max_bytes=100)
        client.close()

        request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
