import json
from typing import TextIO

from scanner import PRODUCT_NAME
from scanner.models import ScanResult, Severity


def write_text_report(result: ScanResult, stream: TextIO) -> None:
    counts = result.counts_by_severity()
    stream.write(f"{PRODUCT_NAME}\n\n")
    stream.write("Scanned:\n")
    stream.write(f"  Spaces discovered: {result.spaces_discovered}\n")
    stream.write(f"  Spaces: {result.spaces_scanned}\n")
    stream.write(f"  Pages: {result.pages_scanned}\n")
    stream.write(f"  Versions: {result.versions_scanned}\n")
    stream.write(f"  Historical versions: {result.historical_versions_scanned}\n")
    stream.write(f"  Comments discovered: {result.comments_discovered}\n")
    stream.write(f"  Comments scanned: {result.comments_scanned}\n")
    stream.write(f"  Attachments discovered: {result.attachments_discovered}\n")
    stream.write(f"  Attachments scanned: {result.attachments_scanned}\n")
    stream.write(f"  Attachments skipped: {result.attachments_skipped}\n")
    stream.write(f"  Attachment bytes: {result.attachment_bytes_scanned}\n\n")
    if result.findings_suppressed:
        stream.write(
            f"Known findings suppressed by baseline: {result.findings_suppressed}\n\n"
        )
    if result.truncated:
        stream.write("  Result truncated by --max-pages\n\n")
    stream.write("Findings:\n")
    for severity in reversed(list(Severity)):
        label = f"{severity.value.capitalize()}:"
        stream.write(f"  {label:<10}{counts[severity.value]}\n")

    if result.findings:
        stream.write("\nDetails:\n")
    for finding in result.findings:
        stream.write(f"\n[{finding.severity.value.upper()}] {finding.rule_name}\n")
        stream.write(f"  Page: {finding.page_title} ({finding.page_id})\n")
        if finding.comment_id:
            stream.write(f"  Comment: {finding.comment_id}\n")
        elif finding.attachment_id:
            stream.write(
                "  Attachment: "
                f"{finding.attachment_name or finding.attachment_id} "
                f"({finding.attachment_id})\n"
            )
        stream.write(f"  Space: {finding.space_key}\n")
        versions = finding.matched_versions or (finding.version,)
        if len(versions) == 1:
            stream.write(f"  Version: {versions[0]}\n")
        else:
            stream.write(
                "  Matched versions: "
                + ", ".join(str(version) for version in versions)
                + "\n"
            )
        stream.write(f"  Location: {finding.location}\n")
        stream.write(f"  Confidence: {finding.confidence:.2f}\n")
        stream.write(f"  Fingerprint: {finding.fingerprint}\n")
        if finding.page_url:
            stream.write(f"  URL: {finding.page_url}\n")

    if result.errors:
        stream.write(f"\nErrors: {len(result.errors)}\n")
        for error in result.errors:
            stream.write(f"  [{error.scope}] {error.message}\n")


def write_json_report(result: ScanResult, stream: TextIO) -> None:
    json.dump(result.to_dict(), stream, indent=2, ensure_ascii=False)
    stream.write("\n")
