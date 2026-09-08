import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

try:
    import requests  # noqa: F401
    import urllib3  # noqa: F401
except ModuleNotFoundError:
    requests = None


class FakeStreamingResponse:
    def __init__(self, content, declared_size=None):
        self.content = content
        self.headers = {}
        if declared_size is not None:
            self.headers["Content-Length"] = str(declared_size)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return None

    def raise_for_status(self):
        return None

    def iter_content(self, chunk_size):
        yield self.content


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
        user_agent = client.session.headers["User-Agent"]
        authorization = client.session.headers["Authorization"]
        client.close()

        self.assertEqual(retry.total, 4)
        self.assertEqual(retry.backoff_factor, 0.25)
        self.assertEqual(set(retry.status_forcelist), {429, 500, 502, 503, 504})
        self.assertEqual(set(retry.allowed_methods), {"GET"})
        self.assertTrue(retry.respect_retry_after_header)
        self.assertEqual(user_agent, "confluleaks/0.1.0")
        self.assertEqual(authorization, "Bearer synthetic-token")

    def test_explicit_basic_auth_is_applied_to_requests(self):
        from scanner.auth import ConfluenceAuth
        from scanner.confluence import ConfluenceClient

        client = ConfluenceClient(
            "https://confluence.example.test",
            auth=ConfluenceAuth.basic("scanner", "synthetic-password"),
        )
        prepared = client.session.prepare_request(
            requests.Request("GET", client.absolute_url("/rest/api/space"))
        )
        client.close()

        self.assertTrue(prepared.headers["Authorization"].startswith("Basic "))

    def test_custom_ca_bundle_is_used_for_tls_verification(self):
        from scanner.confluence import ConfluenceClient

        with tempfile.TemporaryDirectory() as directory:
            ca_bundle = Path(directory) / "company-ca.pem"
            ca_bundle.write_text("synthetic PEM content", encoding="utf-8")
            client = ConfluenceClient(
                "https://confluence.example.test",
                "synthetic-token",
                ca_bundle=ca_bundle,
            )
            with patch.object(
                client.session,
                "get",
                return_value=FakeStreamingResponse(b'{"results": []}'),
            ) as request:
                client.get_spaces()

            self.assertEqual(client.session.verify, str(ca_bundle))
            self.assertEqual(request.call_args.kwargs["verify"], str(ca_bundle))
            client.close()

    def test_custom_ca_bundle_must_be_a_readable_non_empty_file(self):
        from scanner.confluence import ConfluenceClient

        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.pem"
            empty = Path(directory) / "empty.pem"
            empty.touch()

            for ca_bundle in (missing, empty, Path(directory)):
                with self.subTest(ca_bundle=ca_bundle), self.assertRaises(ValueError):
                    ConfluenceClient(
                        "https://confluence.example.test",
                        "synthetic-token",
                        ca_bundle=ca_bundle,
                    )

    def test_tls_failure_has_a_safe_actionable_error(self):
        from scanner.confluence import ConfluenceClient, ConfluenceError

        client = ConfluenceClient(
            "https://confluence.example.test",
            "synthetic-token",
        )
        with patch.object(
            client.session,
            "get",
            side_effect=requests.exceptions.SSLError("synthetic library details"),
        ), self.assertRaises(ConfluenceError) as raised:
            client.get_spaces()
        client.close()

        self.assertIn("TLS certificate verification failed", str(raised.exception))
        self.assertNotIn("synthetic library details", str(raised.exception))

    def test_timeout_error_includes_safe_request_context(self):
        from scanner.confluence import ConfluenceClient, ConfluenceError

        client = ConfluenceClient(
            "https://confluence.example.test",
            "synthetic-token",
            timeout=7.5,
        )
        with patch.object(
            client.session,
            "get",
            side_effect=requests.exceptions.Timeout("synthetic library details"),
        ), self.assertRaises(ConfluenceError) as raised:
            client.get_pages(start=50, limit=25, space_key="ENG")
        client.close()

        message = str(raised.exception)
        self.assertIn("timed out", message)
        self.assertIn("per-request timeout 7.5s", message)
        self.assertIn("space=ENG", message)
        self.assertIn("start=50", message)
        self.assertNotIn("synthetic library details", message)

    def test_connection_error_is_distinguished_from_http_failure(self):
        from scanner.confluence import ConfluenceClient, ConfluenceError

        client = ConfluenceClient(
            "https://confluence.example.test",
            "synthetic-token",
        )
        with patch.object(
            client.session,
            "get",
            side_effect=requests.exceptions.ConnectionError(
                "synthetic library details"
            ),
        ), self.assertRaises(ConfluenceError) as raised:
            client.get_spaces(start=100, limit=50)
        client.close()

        message = str(raised.exception)
        self.assertIn("connection failed after retries", message)
        self.assertIn("start=100", message)
        self.assertNotIn("synthetic library details", message)

    def test_token_and_explicit_auth_cannot_be_combined(self):
        from scanner.auth import ConfluenceAuth
        from scanner.confluence import ConfluenceClient

        with self.assertRaises(ValueError):
            ConfluenceClient(
                "https://confluence.example.test",
                "legacy-token",
                auth=ConfluenceAuth.bearer("explicit-token"),
            )

    def test_rejects_unsafe_or_ambiguous_base_urls(self):
        from scanner.confluence import ConfluenceClient

        invalid_urls = (
            "confluence.example.test",
            "ftp://confluence.example.test",
            "https://user:password@confluence.example.test",
            "https://confluence.example.test?redirect=other",
            "https://confluence.example.test#fragment",
        )
        for url in invalid_urls:
            with self.subTest(url=url), self.assertRaises(ValueError):
                ConfluenceClient(url, "synthetic-token")

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

    def test_comments_use_paginated_storage_body_endpoint(self):
        from scanner.confluence import ConfluenceClient

        client = ConfluenceClient(
            "https://confluence.example.test/confluence",
            "synthetic-token",
        )
        comment = {
            "id": "comment-1",
            "body": {"storage": {"value": "<p>safe</p>"}},
        }

        with patch.object(
            client,
            "_iterate",
            return_value=iter([comment]),
        ) as iterate:
            self.assertEqual(list(client.iter_comments("10")), [comment])
        client.close()

        iterate.assert_called_once_with(
            "/rest/api/content/10/child/comment",
            {
                "expand": "body.storage,version",
                "location": ("footer", "inline", "resolved"),
            },
        )

    def test_preflight_getters_use_bounded_rest_endpoints(self):
        from scanner.confluence import ConfluenceClient

        client = ConfluenceClient(
            "https://confluence.example.test/confluence",
            "synthetic-token",
        )
        with patch.object(client, "_get", return_value={"results": []}) as get:
            client.get_current_user()
            client.get_space("TEAM/OPS")
            client.get_comments("page/10", limit=1)
            client.get_attachments("page/10", limit=1)
        client.close()

        self.assertEqual(get.call_args_list[0].args, ("/rest/api/user/current",))
        self.assertEqual(get.call_args_list[1].args, ("/rest/api/space/TEAM%2FOPS",))
        self.assertEqual(
            get.call_args_list[2].args,
            ("/rest/api/content/page%2F10/child/comment",),
        )
        self.assertEqual(get.call_args_list[2].kwargs["params"]["limit"], 1)
        self.assertEqual(
            get.call_args_list[3].args,
            ("/rest/api/content/page%2F10/child/attachment",),
        )
        self.assertEqual(get.call_args_list[3].kwargs["params"]["limit"], 1)

    def test_declared_oversized_rest_response_is_rejected(self):
        from scanner.confluence import ConfluenceClient, ResponseTooLargeError

        response = FakeStreamingResponse(b"{}", declared_size=100)
        client = ConfluenceClient(
            "https://confluence.example.test",
            "synthetic-token",
            max_response_bytes=10,
        )

        with patch.object(
            client.session, "get", return_value=response
        ), self.assertRaises(ResponseTooLargeError):
            client.get_spaces()
        client.close()

    def test_streamed_oversized_rest_response_is_rejected(self):
        from scanner.confluence import ConfluenceClient, ResponseTooLargeError

        response = FakeStreamingResponse(b'{"results": []}')
        client = ConfluenceClient(
            "https://confluence.example.test",
            "synthetic-token",
            max_response_bytes=5,
        )

        with patch.object(
            client.session, "get", return_value=response
        ), self.assertRaises(ResponseTooLargeError):
            client.get_spaces()
        client.close()

    def test_paginated_collections_reject_non_object_items(self):
        from scanner.confluence import ConfluenceClient, ConfluenceError

        client = ConfluenceClient(
            "https://confluence.example.test",
            "synthetic-token",
        )
        with patch.object(
            client,
            "_get",
            return_value={"results": ["not-an-object"], "_links": {}},
        ), self.assertRaises(ConfluenceError):
            list(client.iter_spaces())
        client.close()


if __name__ == "__main__":
    unittest.main()
