import hashlib
import json
import re
from typing import Any, Dict, List, Optional, TextIO, Tuple
from urllib.parse import quote, urlsplit, urlunsplit

from scanner import PRODUCT_NAME, __version__
from scanner.models import Finding, ScanResult, Severity


SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/"
    "schemas/sarif-schema-2.1.0.json"
)
LOCATION_PATTERN = re.compile(r"^line:(\d+):column:(\d+)$")


def write_sarif_report(
    result: ScanResult,
    stream: TextIO,
    show_secrets: bool = False,
) -> None:
    json.dump(
        build_sarif(result, show_secrets=show_secrets),
        stream,
        indent=2,
        ensure_ascii=False,
    )
    stream.write("\n")


def build_sarif(
    result: ScanResult,
    show_secrets: bool = False,
) -> Dict[str, Any]:
    rule_indices: Dict[str, int] = {}
    rules: List[Dict[str, Any]] = []
    artifact_indices: Dict[str, int] = {}
    artifacts: List[Dict[str, Any]] = []
    sarif_results: List[Dict[str, Any]] = []

    for finding in result.findings:
        rule_index = rule_indices.get(finding.rule_id)
        if rule_index is None:
            rule_index = len(rules)
            rule_indices[finding.rule_id] = rule_index
            rules.append(_rule_descriptor(finding))

        artifact_uri = _artifact_uri(finding)
        artifact_index = artifact_indices.get(artifact_uri)
        if artifact_index is None:
            artifact_index = len(artifacts)
            artifact_indices[artifact_uri] = artifact_index
            artifacts.append(
                {
                    "location": {"uri": artifact_uri, "index": artifact_index},
                    "roles": ["analysisTarget"],
                    "description": {"text": _artifact_description(finding)},
                }
            )

        sarif_results.append(
            _sarif_result(
                finding,
                rule_index,
                artifact_index,
                artifact_uri,
                show_secrets=show_secrets,
            )
        )

    invocation: Dict[str, Any] = {
        "executionSuccessful": not result.errors and not result.truncated,
        "properties": {
            "scanSummary": result.to_dict()["scanned"],
            "truncated": result.truncated,
            "truncationReasons": list(result.truncation_reasons),
            "baselineSuppressedFindings": result.findings_suppressed,
        },
    }
    if result.errors:
        invocation["toolExecutionNotifications"] = [
            {
                "descriptor": {"id": "confluence-scan-error"},
                "level": "error",
                "message": {"text": f"[{error.scope}] {error.message}"},
            }
            for error in result.errors
        ]

    run: Dict[str, Any] = {
        "tool": {
            "driver": {
                "name": PRODUCT_NAME,
                "semanticVersion": __version__,
                "rules": rules,
            }
        },
        "columnKind": "unicodeCodePoints",
        "invocations": [invocation],
        "results": sarif_results,
    }
    if artifacts:
        run["artifacts"] = artifacts

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [run],
    }


def _rule_descriptor(finding: Finding) -> Dict[str, Any]:
    return {
        "id": finding.rule_id,
        "name": finding.rule_name,
        "shortDescription": {"text": finding.rule_name},
        "fullDescription": {
            "text": "Potential secret detected in Confluence content."
        },
        "defaultConfiguration": {"level": _sarif_level(finding.severity)},
        "properties": {
            "tags": ["security", "secrets", "confluence"],
            "security-severity": _security_score(finding.severity),
        },
    }


def _sarif_result(
    finding: Finding,
    rule_index: int,
    artifact_index: int,
    artifact_uri: str,
    show_secrets: bool = False,
) -> Dict[str, Any]:
    region = _region(finding.location)
    physical_location: Dict[str, Any] = {
        "artifactLocation": {
            "uri": artifact_uri,
            "index": artifact_index,
        }
    }
    if region:
        physical_location["region"] = region

    properties: Dict[str, Any] = {
        "confidence": finding.confidence,
        "fingerprint": finding.fingerprint,
        "spaceKey": finding.space_key,
        "pageId": finding.page_id,
        "pageTitle": finding.page_title,
        "pageVersion": finding.version,
        "matchedVersions": list(finding.matched_versions or (finding.version,)),
        "sourceType": _source_type(finding),
    }
    if finding.comment_id:
        properties["commentId"] = finding.comment_id
    elif finding.attachment_id:
        properties["attachmentId"] = finding.attachment_id
        properties["attachmentName"] = (
            finding.attachment_name or finding.attachment_id
        )

    matched_value_is_available = (
        show_secrets and finding.matched_value is not None
    )
    if matched_value_is_available:
        properties["matchedValue"] = finding.matched_value

    message = f"{finding.rule_name} detected in Confluence content."
    if not matched_value_is_available:
        message += " The matched value is intentionally omitted."

    return {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": _sarif_level(finding.severity),
        "message": {"text": message},
        "locations": [{"physicalLocation": physical_location}],
        "partialFingerprints": {
            "primaryLocationLineHash": _location_fingerprint(finding)
        },
        "properties": properties,
    }


def _artifact_uri(finding: Finding) -> str:
    if finding.page_url:
        page_uri = finding.page_url
    else:
        space = quote(finding.space_key, safe="")
        page_id = quote(finding.page_id, safe="")
        page_uri = f"confluence://content/spaces/{space}/pages/{page_id}"

    marker = _source_marker(finding)
    if marker is None:
        return page_uri

    parsed = urlsplit(page_uri)
    fragment = f"{parsed.fragment}&{marker}" if parsed.fragment else marker
    return urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.query, fragment)
    )


def _artifact_description(finding: Finding) -> str:
    if finding.comment_id:
        return f"Confluence comment {finding.comment_id} on page {finding.page_title}"
    if finding.attachment_id:
        name = finding.attachment_name or finding.attachment_id
        return f"Confluence attachment {name} on page {finding.page_title}"
    return f"Confluence page {finding.page_title}"


def _region(location: str) -> Dict[str, int]:
    match = LOCATION_PATTERN.fullmatch(location)
    if not match:
        return {}
    line, column = (int(value) for value in match.groups())
    if line < 1 or column < 1:
        return {}
    return {"startLine": line, "startColumn": column}


def _location_fingerprint(finding: Finding) -> str:
    identity_parts = [
        finding.page_id,
        finding.attachment_id or "",
        finding.rule_id,
        finding.fingerprint,
    ]
    if finding.comment_id:
        identity_parts.append(finding.comment_id)
    material = "\0".join(identity_parts).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _source_type(finding: Finding) -> str:
    if finding.comment_id:
        return "comment"
    if finding.attachment_id:
        return "attachment"
    return "page"


def _source_marker(finding: Finding) -> Optional[str]:
    if finding.comment_id:
        return f"comment={quote(finding.comment_id, safe='')}"
    if finding.attachment_id:
        return f"attachment={quote(finding.attachment_id, safe='')}"
    return None


def _sarif_level(severity: Severity) -> str:
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"


def _security_score(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "9.5",
        Severity.HIGH: "8.0",
        Severity.MEDIUM: "5.5",
        Severity.LOW: "3.0",
    }[severity]
