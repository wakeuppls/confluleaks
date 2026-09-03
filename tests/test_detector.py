import re
import unittest

from scanner.detector import Detector
from scanner.models import Page, Rule, Severity


def make_rule(**overrides):
    values = {
        "id": "password",
        "name": "Password",
        "severity": Severity.HIGH,
        "regex": r"password=(?P<secret>\S+)",
        "confidence": 0.8,
        "keywords": (),
        "require_context": False,
    }
    values.update(overrides)
    values["pattern"] = re.compile(values["regex"])
    return Rule(**values)


class DetectorTest(unittest.TestCase):
    def setUp(self):
        self.page = Page(
            id="42",
            title="Deploy",
            space_key="ENG",
            version=3,
            content="header\npassword=do-not-print-me\nfooter",
        )

    def test_finding_contains_metadata_but_not_secret(self):
        finding = Detector([make_rule()]).scan(self.page)[0]

        serialized = str(finding.to_dict())
        self.assertEqual(finding.location, "line:2:column:10")
        self.assertEqual(finding.confidence, 0.8)
        self.assertNotIn("do-not-print-me", serialized)
        self.assertEqual(len(finding.fingerprint), 64)

    def test_context_can_be_required_and_boosts_confidence(self):
        rule = make_rule(
            regex=r"\b[A-Z0-9]{12}\b",
            keywords=("api_key",),
            require_context=True,
            confidence=0.7,
        )
        page = Page("1", "API", "ENG", 1, "api_key = ABCDEF123456")

        finding = Detector([rule]).scan(page)[0]

        self.assertEqual(finding.confidence, 0.78)

    def test_context_rule_ignores_unlabelled_value(self):
        rule = make_rule(
            regex=r"\b[A-Z0-9]{12}\b",
            keywords=("api_key",),
            require_context=True,
        )
        page = Page("1", "Random", "ENG", 1, "ABCDEF123456")

        self.assertEqual(Detector([rule]).scan(page), [])

    def test_fingerprint_is_stable(self):
        detector = Detector([make_rule()])

        first = detector.scan(self.page)[0].fingerprint
        second = detector.scan(self.page)[0].fingerprint

        self.assertEqual(first, second)

    def test_low_entropy_match_is_ignored(self):
        rule = make_rule(
            regex=r"token=(?P<secret>\S+)",
            min_entropy=3.0,
        )
        page = Page("1", "API", "ENG", 1, "token=AAAAAAAAAAAAAAAAAAAA")

        self.assertEqual(Detector([rule]).scan(page), [])

    def test_allowlist_regex_and_stopword_are_applied_to_secret_only(self):
        regex_rule = make_rule(
            allowlist_patterns=(re.compile(r"^example-"),),
        )
        stopword_rule = make_rule(stopwords=("redacted",))
        example = Page("1", "API", "ENG", 1, "password=example-value-123")
        redacted = Page("1", "API", "ENG", 1, "password=REDACTED-value-123")

        self.assertEqual(Detector([regex_rule]).scan(example), [])
        self.assertEqual(Detector([stopword_rule]).scan(redacted), [])

    def test_context_radius_is_rule_specific(self):
        rule = make_rule(
            regex=r"\bABCDEF123456\b",
            keywords=("token",),
            require_context=True,
            context_radius=5,
        )
        page = Page("1", "API", "ENG", 1, "token          ABCDEF123456")

        self.assertEqual(Detector([rule]).scan(page), [])


if __name__ == "__main__":
    unittest.main()
