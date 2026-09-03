import unittest

try:
    import yaml  # noqa: F401
except ModuleNotFoundError:
    yaml = None

from scanner.detector import Detector
from scanner.models import Page


POSITIVE_CASES = {
    "private-key": "-----BEGIN "
    + "PRIVATE KEY-----\nZmFrZS1rZXk=\n-----END "
    + "PRIVATE KEY-----",
    "pgp-private-key": "-----BEGIN PGP "
    + "PRIVATE KEY BLOCK-----\nZmFrZQ==\n-----END PGP "
    + "PRIVATE KEY BLOCK-----",
    "aws-access-key-id": "AKIA" + "Q7W8E9R0T1Y2U3I4",
    "aws-secret-access-key": "AWS_SECRET_ACCESS_KEY="
    + "aB3dE5gH7jK9mN2pQ4sT6vW8yZ0cD1fG3hJ5kL7m",
    "github-token": "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
    "gitlab-token": "glpat-" + "a1B2c3D4e5F6g7H8i9J0",
    "slack-token": "xoxb-" + "111122223333-444455556666-aBcDeFgHiJkLmNoP",
    "slack-webhook": "https://hooks.slack.com/services/"
    + "T00000000/B00000000/aBcDeFgHiJkLmNoPqRsTuVwX",
    "google-api-key": "AIza" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R",
    "google-oauth-client-secret": "GOCSPX-" + "a1B2c3D4e5F6g7H8i9J0k1L2",
    "stripe-live-secret": "sk_live_" + "a1B2c3D4e5F6g7H8i9J0k1L2",
    "sendgrid-api-key": "SG."
    + "a1B2c3D4e5F6g7H8i9J0."
    + "k1L2m3N4o5P6q7R8s9T0u1V2w3X4",
    "npm-access-token": "npm_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
    "pypi-upload-token": "pypi-AgEIcHlwaS5vcmc" + "a1B2c3D4e5F6g7H8i9J0" * 3,
    "telegram-bot-token": "123456789:" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R",
    "new-relic-key": "NRAK-" + "A1B2C3D4E5F6G7H8I9J0K1L2M3N",
    "hashicorp-vault-token": "hvs." + "a1B2c3D4e5F6g7H8i9J0k1L2",
    "digitalocean-token": "dop_v1_" + "a1b2c3d4e5f60718" * 4,
    "database-connection-string": "postgresql://scanner:"
    + "SyntheticPass123@db.example.test/app",
    "http-basic-auth": "https://scanner:" + "SyntheticPass123@example.test/api",
    "jwt": "Authorization: Bearer "
    + "eyJhbGciOiJIUzI1NiJ9."
    + "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    + "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    "datadog-api-key": "DD_API_KEY=" + "a1b2c3d4e5f60718293a4b5c6d7e8f90",
    "azure-storage-account-key": "AccountKey="
    + "aB3dE5gH7jK9mN2pQ4sT6vW8yZ0cD1fG3hJ5kL7m" * 2
    + "Q8rT9u==",
    "azure-sas-signature": "https://blob.example.test/a?sv=2024-01-01&sp=r&sig="
    + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8%2F%3D",
    "docker-config-auth": '"auth": "'
    + "c2Nhbm5lcl91c2VyOlN5bnRoZXRpY1Bhc3N3MHJkIQ=="
    + '"',
    "generic-password": 'password = "' + "Correct Horse Battery Staple!" + '"',
    "generic-api-key": "client_secret=" + "a1B2c3D4e5F6g7H8i9J0k1L2",
}


NEGATIVE_CASES = {
    "aws-access-key-id": "AKIA" + "IOSFODNN7EXAMPLE",
    "aws-secret-access-key": "AWS_SECRET_ACCESS_KEY=" + "A" * 40,
    "github-token": "ghp_" + "0" * 36,
    "google-api-key": "AIza-too-short",
    "stripe-live-secret": "pk_live_a1B2c3D4e5F6g7H8i9J0",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signatureWithoutContext",
    "datadog-api-key": "DD_API_KEY=" + "a" * 32,
    "docker-config-auth": '"auth": "AAAAAAAAAAAAAAAAAAAA"',
    "generic-password": "password=changeme",
    "generic-api-key": "api_key=00000000000000000000",
}


@unittest.skipIf(yaml is None, "PyYAML dependency is not installed")
class DefaultRulePackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from scanner.rules import load_rules

        cls.rules = {rule.id: rule for rule in load_rules()}

    def scan_rule(self, rule_id, content):
        page = Page("1", "Rule fixture", "TEST", 1, content)
        return Detector([self.rules[rule_id]]).scan(page)

    def test_every_rule_has_a_positive_fixture(self):
        self.assertEqual(set(self.rules), set(POSITIVE_CASES))

        for rule_id, content in POSITIVE_CASES.items():
            with self.subTest(rule=rule_id):
                findings = self.scan_rule(rule_id, content)
                self.assertEqual(len(findings), 1)
                self.assertNotIn(content, str(findings[0].to_dict()))

    def test_common_placeholders_and_near_misses_are_ignored(self):
        for rule_id, content in NEGATIVE_CASES.items():
            with self.subTest(rule=rule_id):
                self.assertEqual(self.scan_rule(rule_id, content), [])


if __name__ == "__main__":
    unittest.main()
