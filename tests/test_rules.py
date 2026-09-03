import tempfile
import unittest
from pathlib import Path

try:
    import yaml  # noqa: F401
except ModuleNotFoundError:
    yaml = None


@unittest.skipIf(yaml is None, "PyYAML dependency is not installed")
class RulesTest(unittest.TestCase):
    def test_default_rules_load(self):
        from scanner.rules import load_rules

        rules = load_rules()

        self.assertGreaterEqual(len(rules), 20)
        self.assertTrue(any(rule.id == "github-token" for rule in rules))

    def test_extended_rule_settings_load(self):
        from scanner.rules import load_rules

        content = """\
rules:
  - id: extended
    severity: medium
    regex: 'token=(?P<secret>\\S+)'
    min_entropy: 3.2
    context_radius: 40
    allowlist:
      regexes:
        - '^example-'
      stopwords:
        - redacted
"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rules.yaml"
            path.write_text(content, encoding="utf-8")
            rule = load_rules(path)[0]

        self.assertEqual(rule.min_entropy, 3.2)
        self.assertEqual(rule.context_radius, 40)
        self.assertEqual(rule.stopwords, ("redacted",))
        self.assertTrue(rule.allowlist_patterns[0].search("EXAMPLE-value"))

    def test_duplicate_ids_are_rejected(self):
        from scanner.rules import RuleConfigurationError, load_rules

        content = """\
rules:
  - id: duplicate
    severity: high
    regex: abc
  - id: duplicate
    severity: low
    regex: def
"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rules.yaml"
            path.write_text(content, encoding="utf-8")

            with self.assertRaisesRegex(RuleConfigurationError, "duplicate rule id"):
                load_rules(path)


if __name__ == "__main__":
    unittest.main()
