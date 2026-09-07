import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanner.config import (
    ConfigurationError,
    discover_config_path,
    load_config,
)
from scanner.main import _parse_arguments, build_parser


class ConfigurationTest(unittest.TestCase):
    def _write(self, directory: str, content: str) -> Path:
        path = Path(directory) / "confluleaks.yaml"
        path.write_text(content, encoding="utf-8")
        return path

    def test_loads_typed_values_and_resolves_relative_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory,
                """
version: 1
url: https://confluence.example.test/confluence
auth: BASIC
rules: rules.yaml
baseline: state/baseline.json
spaces: [ENG, OPS, ENG]
exclude_spaces: []
comments: true
page_size: 25
timeout: 10
retries: 2
request_delay: 0.1
fail_on: high
""",
            )

            configuration = load_config(path)

        self.assertEqual(configuration.path, path)
        self.assertEqual(configuration.values["auth"], "basic")
        self.assertEqual(configuration.values["spaces"], ["ENG", "OPS"])
        self.assertTrue(configuration.values["comments"])
        self.assertEqual(configuration.values["page_size"], 25)
        self.assertEqual(configuration.values["timeout"], 10.0)
        self.assertEqual(
            configuration.values["rules"],
            Path(directory) / "rules.yaml",
        )
        self.assertEqual(
            configuration.values["baseline"],
            Path(directory) / "state/baseline.json",
        )

    def test_tracked_example_is_valid(self):
        path = Path(__file__).resolve().parents[1] / "confluleaks.example.yaml"

        configuration = load_config(path)

        self.assertEqual(configuration.values["auth"], "bearer")
        self.assertEqual(configuration.values["spaces"], ["ENG"])
        self.assertNotIn("token", configuration.values)

    def test_rejects_unknown_fields_and_credentials(self):
        fixtures = (
            "version: 1\nunknown_option: true\n",
            "version: 1\ntoken: do-not-store-this\n",
            "version: 1\npassword: do-not-store-this\n",
        )
        with tempfile.TemporaryDirectory() as directory:
            for content in fixtures:
                with self.subTest(content=content):
                    path = self._write(directory, content)
                    with self.assertRaises(ConfigurationError):
                        load_config(path)

    def test_rejects_invalid_version_and_types(self):
        fixtures = (
            "version: 2\n",
            'version: 1\ncomments: "yes"\n',
            "version: 1\nspaces: ENG\n",
            "version: 1\npage_size: 0\n",
            "version: 1\ntimeout: .inf\n",
        )
        with tempfile.TemporaryDirectory() as directory:
            for content in fixtures:
                with self.subTest(content=content):
                    path = self._write(directory, content)
                    with self.assertRaises(ConfigurationError):
                        load_config(path)

    def test_discovers_explicit_environment_and_local_paths_in_order(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            local = self._write(directory, "version: 1\n")
            environment = root / "environment.yaml"
            explicit = root / "explicit.yaml"

            self.assertEqual(
                discover_config_path(
                    ["--config", str(explicit)],
                    environ={"CONFLULEAKS_CONFIG": str(environment)},
                    cwd=root,
                ),
                explicit,
            )
            self.assertEqual(
                discover_config_path(
                    [],
                    environ={"CONFLULEAKS_CONFIG": str(environment)},
                    cwd=root,
                ),
                environment,
            )
            self.assertEqual(discover_config_path([], environ={}, cwd=root), local)
            self.assertIsNone(
                discover_config_path(
                    ["--no-config"],
                    environ={"CONFLULEAKS_CONFIG": str(environment)},
                    cwd=root,
                )
            )

    def test_cli_replaces_configured_lists_and_can_disable_booleans(self):
        parser = build_parser(
            {
                "spaces": ["FROM_CONFIG"],
                "comments": True,
                "timeout": 30.0,
            }
        )

        args = parser.parse_args(
            ["--space", "FROM_CLI", "--no-comments", "--timeout", "5"]
        )

        self.assertEqual(args.space, ["FROM_CLI"])
        self.assertFalse(args.comments)
        self.assertEqual(args.timeout, 5.0)

    def test_environment_url_and_auth_override_file_values(self):
        with patch.dict(
            os.environ,
            {
                "CONFLUENCE_URL": "https://environment.example.test",
                "CONFLUENCE_AUTH": "BEARER",
            },
            clear=True,
        ):
            parser = build_parser(
                {
                    "url": "https://configuration.example.test",
                    "auth": "basic",
                }
            )
            args = parser.parse_args([])

        self.assertEqual(args.url, "https://environment.example.test")
        self.assertEqual(args.auth, "bearer")

    def test_explicit_config_is_applied_by_main_argument_loader(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory,
                "version: 1\nspaces: [FROM_CONFIG]\ncomments: true\n",
            )

            _, args = _parse_arguments(
                ["--config", str(path), "--space", "FROM_CLI", "--no-comments"]
            )

        self.assertEqual(args.space, ["FROM_CLI"])
        self.assertFalse(args.comments)

    def test_local_config_is_loaded_automatically(self):
        with tempfile.TemporaryDirectory() as directory:
            self._write(directory, "version: 1\nspaces: [LOCAL]\ncomments: true\n")
            with patch.dict(os.environ, {}, clear=True), patch(
                "scanner.config.Path.cwd",
                return_value=Path(directory),
            ):
                _, args = _parse_arguments([])

        self.assertEqual(args.space, ["LOCAL"])
        self.assertTrue(args.comments)

    def test_no_config_ignores_environment_selected_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, "version: 1\ncomments: true\n")
            with patch.dict(
                os.environ,
                {"CONFLULEAKS_CONFIG": str(path)},
                clear=True,
            ):
                _, args = _parse_arguments(["--no-config"])

        self.assertFalse(args.comments)


if __name__ == "__main__":
    unittest.main()
