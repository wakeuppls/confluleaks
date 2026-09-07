import unittest
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

    def test_token_and_explicit_auth_cannot_be_combined(self):
        from scanner.auth import ConfluenceAuth
        from scanner.confluence import ConfluenceClient

        with self.assertRaises(ValueError):
            ConfluenceClient(
                "https://confluence.example.test",
                "legacy-token",
                auth=ConfluenceAuth.bearer("explicit-token"),
            )

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
            client.get_space("TEAM/OPS")
            client.get_comments("page/10", limit=1)
            client.get_attachments("page/10", limit=1)
        client.close()

        self.assertEqual(get.call_args_list[0].args, ("/rest/api/space/TEAM%2FOPS",))
        self.assertEqual(
            get.call_args_list[1].args,
            ("/rest/api/content/page%2F10/child/comment",),
        )
        self.assertEqual(get.call_args_list[1].kwargs["params"]["limit"], 1)
        self.assertEqual(
            get.call_args_list[2].args,
            ("/rest/api/content/page%2F10/child/attachment",),
        )
        self.assertEqual(get.call_args_list[2].kwargs["params"]["limit"], 1)

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


if __name__ == "__main__":
    unittest.main()
