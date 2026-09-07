import argparse
import math
import os
import sys
from pathlib import Path
from typing import Optional, Sequence

from scanner import PRODUCT_COMMAND, __version__
from scanner.auth import AuthConfigurationError, AuthMethod, ConfluenceAuth
from scanner.baseline import (
    BaselineError,
    apply_baseline,
    load_baseline,
    write_baseline,
)
from scanner.confluence import ConfluenceClient, ConfluenceError
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PRODUCT_COMMAND,
        description="Scan current Confluence pages for accidentally exposed secrets",
    )
    parser.add_argument(
        "--url",
        default=os.environ.get("CONFLUENCE_URL"),
        help="Confluence base URL (or set CONFLUENCE_URL)",
    )
    parser.add_argument(
        "--auth",
        choices=tuple(method.value for method in AuthMethod),
        default=os.environ.get(
            "CONFLUENCE_AUTH",
            AuthMethod.BEARER.value,
        ).casefold(),
        help="authentication method (or set CONFLUENCE_AUTH; default: bearer)",
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
        default=DEFAULT_RULES_PATH,
        help="YAML rules file",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "sarif"),
        default="text",
    )
    parser.add_argument("--page-size", type=int, default=50)
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument(
        "--space",
        action="append",
        default=[],
        metavar="KEY",
        help="scan only this space; can be repeated",
    )
    parser.add_argument(
        "--exclude-space",
        action="append",
        default=[],
        metavar="KEY",
        help="skip this space; can be repeated",
    )
    parser.add_argument(
        "--include-personal-spaces",
        action="store_true",
        help="include personal spaces when --space is not used",
    )
    parser.add_argument(
        "--include-archived-spaces",
        action="store_true",
        help="include archived spaces when --space is not used",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        help="stop after scanning at most this many current pages",
    )
    parser.add_argument(
        "--history",
        action="store_true",
        help="scan historical page versions in addition to current content",
    )
    parser.add_argument(
        "--history-limit",
        type=int,
        help="scan at most this many previous versions per page",
    )
    parser.add_argument(
        "--comments",
        action="store_true",
        help="scan current page comments",
    )
    parser.add_argument(
        "--attachments",
        action="store_true",
        help="scan supported text attachments",
    )
    parser.add_argument(
        "--max-attachment-size-mb",
        type=float,
        default=5.0,
        metavar="MB",
        help="skip attachments larger than this many MiB (default: 5)",
    )
    parser.add_argument(
        "--max-response-size-mb",
        type=float,
        default=16.0,
        metavar="MB",
        help="abort a REST response larger than this many MiB (default: 16)",
    )
    parser.add_argument(
        "--max-document-size-mb",
        type=float,
        default=5.0,
        metavar="MB",
        help="skip extracted documents larger than this many MiB (default: 5)",
    )
    parser.add_argument(
        "--regex-timeout",
        type=float,
        default=0.25,
        metavar="SECONDS",
        help="timeout for each regex operation (default: 0.25)",
    )
    parser.add_argument(
        "--max-findings",
        type=int,
        default=10_000,
        metavar="N",
        help="stop after retaining this many findings (default: 10000)",
    )
    parser.add_argument(
        "--max-findings-per-document",
        type=int,
        default=1_000,
        metavar="N",
        help="retain at most this many findings per document (default: 1000)",
    )
    parser.add_argument(
        "--max-runtime",
        type=float,
        default=3_600.0,
        metavar="SECONDS",
        help="soft total scan runtime limit (default: 3600)",
    )
    parser.add_argument(
        "--continue-on-error",
        action="store_true",
        help="continue other spaces/pages after a recoverable request error",
    )
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--backoff", type=float, default=0.5)
    parser.add_argument(
        "--request-delay",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help="minimum delay between Confluence requests",
    )
    parser.add_argument(
        "--fail-on",
        choices=tuple(severity.value for severity in Severity),
        help="exit with status 2 if this severity or higher is found",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        help="suppress findings already present in this baseline",
    )
    parser.add_argument(
        "--write-baseline",
        type=Path,
        metavar="PATH",
        help="atomically write a baseline from a complete successful scan",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.url:
        parser.error("Confluence URL is required via --url or CONFLUENCE_URL")
    if args.preflight and args.format == "sarif":
        parser.error("--preflight supports only text and json output")
    if args.preflight and (args.baseline or args.write_baseline or args.fail_on):
        parser.error(
            "--baseline, --write-baseline, and --fail-on cannot be used with "
            "--preflight"
        )
    try:
        auth = _load_auth(args.auth)
    except AuthConfigurationError as error:
        parser.error(str(error))
    if args.page_size < 1:
        parser.error("--page-size must be greater than zero")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    if args.max_pages is not None and args.max_pages < 1:
        parser.error("--max-pages must be greater than zero")
    if args.retries < 0:
        parser.error("--retries must not be negative")
    if args.backoff < 0:
        parser.error("--backoff must not be negative")
    if args.request_delay < 0:
        parser.error("--request-delay must not be negative")
    if args.history_limit is not None and args.history_limit < 1:
        parser.error("--history-limit must be greater than zero")
    if (
        not math.isfinite(args.max_attachment_size_mb)
        or args.max_attachment_size_mb <= 0
    ):
        parser.error("--max-attachment-size-mb must be greater than zero")
    if (
        not math.isfinite(args.max_response_size_mb)
        or args.max_response_size_mb <= 0
    ):
        parser.error("--max-response-size-mb must be greater than zero")
    if (
        not math.isfinite(args.max_document_size_mb)
        or args.max_document_size_mb <= 0
    ):
        parser.error("--max-document-size-mb must be greater than zero")
    if not math.isfinite(args.regex_timeout) or args.regex_timeout <= 0:
        parser.error("--regex-timeout must be greater than zero")
    if args.max_findings < 1:
        parser.error("--max-findings must be greater than zero")
    if args.max_findings_per_document < 1:
        parser.error("--max-findings-per-document must be greater than zero")
    if not math.isfinite(args.max_runtime) or args.max_runtime <= 0:
        parser.error("--max-runtime must be greater than zero")
    if args.history_limit is not None:
        args.history = True
    duplicate_space_filters = {
        key.casefold() for key in args.space
    } & {key.casefold() for key in args.exclude_space}
    if duplicate_space_filters:
        parser.error("the same space cannot be included and excluded")

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


if __name__ == "__main__":
    raise SystemExit(main())
