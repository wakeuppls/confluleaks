import base64
import unittest

try:
    import requests
    from scanner.auth import AuthConfigurationError, AuthMethod, ConfluenceAuth
except ModuleNotFoundError:
    requests = None


@unittest.skipIf(requests is None, "HTTP dependencies are not installed")
class ConfluenceAuthTest(unittest.TestCase):
    def test_bearer_auth_sets_header_without_exposing_token_in_repr(self):
        auth = ConfluenceAuth.bearer("synthetic-bearer-token")
        session = requests.Session()

        auth.apply(session)

        self.assertEqual(auth.method, AuthMethod.BEARER)
        self.assertEqual(
            session.headers["Authorization"],
            "Bearer synthetic-bearer-token",
        )
        self.assertNotIn("synthetic-bearer-token", repr(auth))
        session.close()

    def test_basic_auth_prepares_standard_authorization_header(self):
        auth = ConfluenceAuth.basic(
            "scanner@example.test",
            "synthetic-api-token",
        )
        session = requests.Session()

        auth.apply(session)
        prepared = session.prepare_request(
            requests.Request("GET", "https://confluence.example.test/rest/api/space")
        )
        scheme, encoded = prepared.headers["Authorization"].split(" ", 1)

        self.assertEqual(auth.method, AuthMethod.BASIC)
        self.assertEqual(scheme, "Basic")
        self.assertEqual(
            base64.b64decode(encoded).decode("utf-8"),
            "scanner@example.test:synthetic-api-token",
        )
        self.assertNotIn("synthetic-api-token", repr(auth))
        session.close()

    def test_empty_secrets_and_invalid_basic_username_are_rejected(self):
        with self.assertRaises(AuthConfigurationError):
            ConfluenceAuth.bearer("")
        with self.assertRaises(AuthConfigurationError):
            ConfluenceAuth.basic("", "secret")
        with self.assertRaises(AuthConfigurationError):
            ConfluenceAuth.basic("user:name", "secret")
        with self.assertRaises(AuthConfigurationError):
            ConfluenceAuth.basic("user\nname", "secret")

    def test_basic_username_is_trimmed(self):
        auth = ConfluenceAuth.basic("  scanner@example.test  ", "secret")

        self.assertEqual(auth.username, "scanner@example.test")


if __name__ == "__main__":
    unittest.main()
