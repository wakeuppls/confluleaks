import argparse
import math
import os
import sys
from pathlib import Path
from typing import Optional, Sequence

from scanner import PRODUCT_COMMAND, __version__
from scanner.baseline import (
    BaselineError,
    apply_baseline,
    load_baseline,
    write_baseline,
)
from scanner.confluence import ConfluenceClient, ConfluenceError
from scanner.detector import Detector
from scanner.models import Severity
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
    token = os.environ.get("CONFLUENCE_TOKEN")

    if not args.url:
        parser.error("Confluence URL is required via --url or CONFLUENCE_URL")
    if token is None:
        parser.error("CONFLUENCE_TOKEN is required")
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
    if args.history_limit is not None:
        args.history = True
    duplicate_space_filters = {
        key.casefold() for key in args.space
    } & {key.casefold() for key in args.exclude_space}
    if duplicate_space_filters:
        parser.error("the same space cannot be included and excluded")

    try:
        baseline = load_baseline(args.baseline) if args.baseline else None
        rules = load_rules(args.rules)
        with ConfluenceClient(
            args.url,
            token,
            timeout=args.timeout,
            page_size=args.page_size,
            retries=args.retries,
            backoff=args.backoff,
            request_delay=args.request_delay,
        ) as client:
            result = SecretScanner(
                client,
                Detector(rules),
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
            ).scan()

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

    if result.errors:
        return 1
    if args.fail_on:
        threshold = Severity(args.fail_on).rank
        if any(finding.severity.rank >= threshold for finding in result.findings):
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
