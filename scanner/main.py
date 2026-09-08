import argparse
import math
import os
import sys
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence, Tuple

from scanner import PRODUCT_COMMAND, __version__
from scanner.auth import AuthConfigurationError, AuthMethod, ConfluenceAuth
from scanner.baseline import (
    BaselineError,
    apply_baseline,
    load_baseline,
    write_baseline,
)
from scanner.confluence import ConfluenceClient, ConfluenceError
from scanner.config import ConfigurationError, discover_config_path, load_config
from scanner.detector import Detector
from scanner.models import Severity
from scanner.preflight import (
    PreflightChecker,
    write_json_preflight,
    write_text_preflight,
)
from scanner.report import write_json_report, write_text_report
from scanner.rules import DEFAULT_RULES_PATH, RuleConfigurationError, load_rules
from scanner.sarif import write_sarif_report
from scanner.service import SecretScanner


class OverrideConfigAppendAction(argparse.Action):
    """Replace a configured list when the option first appears on the CLI."""

    def __call__(self, parser, namespace, value, option_string=None) -> None:
        marker = f"_cli_override_{self.dest}"
        if not getattr(namespace, marker, False):
            setattr(namespace, self.dest, [])
            setattr(namespace, marker, True)
        getattr(namespace, self.dest).append(value)


class ExplicitBooleanOptionalAction(argparse.BooleanOptionalAction):
    """Record that a Boolean option was explicitly supplied on the CLI."""

    def __call__(self, parser, namespace, values, option_string=None) -> None:
        super().__call__(parser, namespace, values, option_string)
        setattr(namespace, f"_cli_explicit_{self.dest}", True)


def _space_key_argument(value: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise argparse.ArgumentTypeError("space key must not be empty")
    return normalized


def build_parser(
    config_values: Optional[Mapping[str, Any]] = None,
) -> argparse.ArgumentParser:
    configured = dict(config_values or {})

    def setting(name: str, default: Any) -> Any:
        return configured.get(name, default)

    parser = argparse.ArgumentParser(
        prog=PRODUCT_COMMAND,
        description="Scan current Confluence pages for accidentally exposed secrets",
    )
    parser.add_argument(
        "--url",
        default=os.environ.get("CONFLUENCE_URL", setting("url", None)),
        help="Confluence base URL (or set CONFLUENCE_URL)",
    )
    parser.add_argument(
        "--auth",
        choices=tuple(method.value for method in AuthMethod),
        default=os.environ.get(
            "CONFLUENCE_AUTH",
            setting("auth", AuthMethod.BEARER.value),
        ).casefold(),
        help="authentication method (or set CONFLUENCE_AUTH; default: bearer)",
    )
    parser.add_argument(
        "--ca-bundle",
        type=Path,
        default=os.environ.get(
            "CONFLUENCE_CA_BUNDLE",
            setting("ca_bundle", None),
        ),
        metavar="PATH",
        help="PEM CA bundle for TLS verification (or set CONFLUENCE_CA_BUNDLE)",
    )
    config_group = parser.add_mutually_exclusive_group()
    config_group.add_argument(
        "--config",
        type=Path,
        help="load YAML configuration from this path",
    )
    config_group.add_argument(
        "--no-config",
        action="store_true",
        help="ignore configured and local YAML files",
    )
    parser.add_argument(
        "--preflight",
        action="store_true",
        help="check authentication and requested REST capabilities without scanning",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--rules",
        type=Path,
        default=setting("rules", DEFAULT_RULES_PATH),
        help="YAML rules file",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "sarif"),
        default=setting("format", "text"),
    )
    parser.add_argument("--page-size", type=int, default=setting("page_size", 50))
    parser.add_argument("--timeout", type=float, default=setting("timeout", 20.0))
    parser.add_argument(
        "--space",
        action=OverrideConfigAppendAction,
        type=_space_key_argument,
        default=list(setting("spaces", [])),
        metavar="KEY",
        help="scan only this space; can be repeated",
    )
    parser.add_argument(
        "--exclude-space",
        action=OverrideConfigAppendAction,
        type=_space_key_argument,
        default=list(setting("exclude_spaces", [])),
        metavar="KEY",
        help="skip this space; can be repeated",
    )
    parser.add_argument(
        "--include-personal-spaces",
        action=argparse.BooleanOptionalAction,
        default=setting("include_personal_spaces", False),
        help="include personal spaces when --space is not used",
    )
    parser.add_argument(
        "--include-archived-spaces",
        action=argparse.BooleanOptionalAction,
        default=setting("include_archived_spaces", False),
        help="include archived spaces when --space is not used",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=setting("max_pages", None),
        help="stop after scanning at most this many current pages",
    )
    parser.add_argument(
        "--history",
        action=ExplicitBooleanOptionalAction,
        default=setting("history", False),
        help="scan historical page versions in addition to current content",
    )
    parser.add_argument(
        "--history-limit",
        type=int,
        default=setting("history_limit", None),
        help="scan at most this many previous versions per page",
    )
    parser.add_argument(
        "--comments",
        action=argparse.BooleanOptionalAction,
        default=setting("comments", False),
        help="scan current page comments",
    )
    parser.add_argument(
        "--attachments",
        action=argparse.BooleanOptionalAction,
        default=setting("attachments", False),
        help="scan supported text attachments",
    )
    parser.add_argument(
        "--max-attachment-size-mb",
        type=float,
        default=setting("max_attachment_size_mb", 5.0),
        metavar="MB",
        help="skip attachments larger than this many MiB (default: 5)",
    )
    parser.add_argument(
        "--max-response-size-mb",
        type=float,
        default=setting("max_response_size_mb", 16.0),
        metavar="MB",
        help="abort a REST response larger than this many MiB (default: 16)",
    )
    parser.add_argument(
        "--max-document-size-mb",
        type=float,
        default=setting("max_document_size_mb", 5.0),
        metavar="MB",
        help="skip extracted documents larger than this many MiB (default: 5)",
    )
    parser.add_argument(
        "--regex-timeout",
        type=float,
        default=setting("regex_timeout", 0.25),
        metavar="SECONDS",
        help="timeout for each regex operation (default: 0.25)",
    )
    parser.add_argument(
        "--max-findings",
        type=int,
        default=setting("max_findings", 10_000),
        metavar="N",
        help="stop after retaining this many findings (default: 10000)",
    )
    parser.add_argument(
        "--max-findings-per-document",
        type=int,
        default=setting("max_findings_per_document", 1_000),
        metavar="N",
        help="retain at most this many findings per document (default: 1000)",
    )
    parser.add_argument(
        "--max-runtime",
        type=float,
        default=setting("max_runtime", 3_600.0),
        metavar="SECONDS",
        help="soft total scan runtime limit (default: 3600)",
    )
    parser.add_argument(
        "--continue-on-error",
        action=argparse.BooleanOptionalAction,
        default=setting("continue_on_error", False),
        help="continue other spaces/pages after a recoverable request error",
    )
    parser.add_argument("--retries", type=int, default=setting("retries", 3))
    parser.add_argument("--backoff", type=float, default=setting("backoff", 0.5))
    parser.add_argument(
        "--request-delay",
        type=float,
        default=setting("request_delay", 0.0),
        metavar="SECONDS",
        help="minimum delay between Confluence requests",
    )
    parser.add_argument(
        "--fail-on",
        choices=tuple(severity.value for severity in Severity),
        default=setting("fail_on", None),
        help="exit with status 2 if this severity or higher is found",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=setting("baseline", None),
        help="suppress findings already present in this baseline",
    )
    parser.add_argument(
        "--write-baseline",
        type=Path,
        metavar="PATH",
        help="atomically write a baseline from a complete successful scan",
    )
    return parser


def _parse_arguments(
    argv: Optional[Sequence[str]] = None,
) -> Tuple[argparse.ArgumentParser, argparse.Namespace]:
    raw_argv = list(argv) if argv is not None else sys.argv[1:]
    if any(option in raw_argv for option in ("-h", "--help", "--version")):
        parser = build_parser()
        return parser, parser.parse_args(raw_argv)

    config_path = discover_config_path(raw_argv)
    configuration = load_config(config_path)
    parser = build_parser(configuration.values)
    return parser, parser.parse_args(raw_argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        parser, args = _parse_arguments(argv)
    except ConfigurationError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    if not args.url:
        parser.error("Confluence URL is required via --url or CONFLUENCE_URL")
    if args.preflight and args.format == "sarif":
        parser.error("--preflight supports only text and json output")
    if args.preflight and args.write_baseline:
        parser.error("--write-baseline cannot be used with --preflight")
    _validate_arguments(parser, args)
    try:
        auth = _load_auth(args.auth)
    except AuthConfigurationError as error:
        parser.error(str(error))

    try:
        with ConfluenceClient(
            args.url,
            timeout=args.timeout,
            page_size=args.page_size,
            retries=args.retries,
            backoff=args.backoff,
            request_delay=args.request_delay,
            max_response_bytes=max(
                1,
                int(args.max_response_size_mb * 1024 * 1024),
            ),
            auth=auth,
            ca_bundle=args.ca_bundle,
        ) as client:
            if args.preflight:
                preflight_result = PreflightChecker(
                    client,
                    space_keys=args.space,
                    check_history=args.history,
                    check_comments=args.comments,
                    check_attachments=args.attachments,
                ).run()
            else:
                baseline = load_baseline(args.baseline) if args.baseline else None
                rules = load_rules(args.rules)
                result = SecretScanner(
                    client,
                    Detector(rules, regex_timeout=args.regex_timeout),
                    include_history=args.history,
                    history_limit=args.history_limit,
                    include_spaces=args.space,
                    exclude_spaces=args.exclude_space,
                    include_personal_spaces=args.include_personal_spaces,
                    include_archived_spaces=args.include_archived_spaces,
                    max_pages=args.max_pages,
                    continue_on_error=args.continue_on_error,
                    include_comments=args.comments,
                    include_attachments=args.attachments,
                    max_attachment_bytes=max(
                        1,
                        int(args.max_attachment_size_mb * 1024 * 1024),
                    ),
                    max_document_bytes=max(
                        1,
                        int(args.max_document_size_mb * 1024 * 1024),
                    ),
                    max_findings=args.max_findings,
                    max_findings_per_document=args.max_findings_per_document,
                    max_runtime_seconds=args.max_runtime,
                ).scan()

        if args.preflight:
            if args.format == "json":
                write_json_preflight(preflight_result, sys.stdout)
            else:
                write_text_preflight(preflight_result, sys.stdout)
            return 0 if preflight_result.ok else 1

        observed_findings = tuple(result.findings)
        if args.write_baseline:
            if result.errors or result.truncated:
                raise BaselineError(
                    "refusing to write a baseline from a partial scan"
                )
            write_baseline(args.write_baseline, observed_findings)
        if baseline is not None:
            apply_baseline(result, baseline)
    except (
        BaselineError,
        ConfluenceError,
        RuleConfigurationError,
        KeyError,
        TypeError,
        ValueError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    if args.format == "json":
        write_json_report(result, sys.stdout)
    elif args.format == "sarif":
        write_sarif_report(result, sys.stdout)
    else:
        write_text_report(result, sys.stdout)

    if result.errors or result.truncated:
        return 1
    if args.fail_on:
        threshold = Severity(args.fail_on).rank
        if any(finding.severity.rank >= threshold for finding in result.findings):
            return 2
    return 0


def _load_auth(method: str) -> ConfluenceAuth:
    secret = os.environ.get("CONFLUENCE_TOKEN")
    if secret is None:
        raise AuthConfigurationError("CONFLUENCE_TOKEN is required")
    auth_method = AuthMethod(method)
    if auth_method is AuthMethod.BEARER:
        return ConfluenceAuth.bearer(secret)

    username = os.environ.get("CONFLUENCE_USERNAME")
    if username is None:
        raise AuthConfigurationError(
            "CONFLUENCE_USERNAME is required for Basic authentication"
        )
    return ConfluenceAuth.basic(username, secret)


def _validate_arguments(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
) -> None:
    positive_integers = (
        ("--page-size", args.page_size),
        ("--max-pages", args.max_pages),
        ("--history-limit", args.history_limit),
        ("--max-findings", args.max_findings),
        ("--max-findings-per-document", args.max_findings_per_document),
    )
    for option, value in positive_integers:
        if value is not None and value < 1:
            parser.error(f"{option} must be greater than zero")

    if args.retries < 0:
        parser.error("--retries must not be negative")

    positive_numbers = (
        ("--timeout", args.timeout),
        ("--max-attachment-size-mb", args.max_attachment_size_mb),
        ("--max-response-size-mb", args.max_response_size_mb),
        ("--max-document-size-mb", args.max_document_size_mb),
        ("--regex-timeout", args.regex_timeout),
        ("--max-runtime", args.max_runtime),
    )
    for option, value in positive_numbers:
        if not math.isfinite(value) or value <= 0:
            parser.error(f"{option} must be a positive finite number")

    nonnegative_numbers = (
        ("--backoff", args.backoff),
        ("--request-delay", args.request_delay),
    )
    for option, value in nonnegative_numbers:
        if not math.isfinite(value) or value < 0:
            parser.error(f"{option} must be a finite non-negative number")

    history_was_disabled = (
        getattr(args, "_cli_explicit_history", False) and not args.history
    )
    if history_was_disabled:
        args.history_limit = None
    elif args.history_limit is not None:
        args.history = True

    args.space = _unique_space_keys(args.space)
    args.exclude_space = _unique_space_keys(args.exclude_space)
    included_spaces = {key.casefold() for key in args.space}
    excluded_spaces = {key.casefold() for key in args.exclude_space}
    if included_spaces & excluded_spaces:
        parser.error("the same space cannot be included and excluded")


def _unique_space_keys(keys: Sequence[str]) -> list:
    unique = {}
    for key in keys:
        normalized = key.strip()
        unique.setdefault(normalized.casefold(), normalized)
    return list(unique.values())


if __name__ == "__main__":
    raise SystemExit(main())
