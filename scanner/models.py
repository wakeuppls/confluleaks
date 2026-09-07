from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Pattern, Tuple


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: Severity
    regex: str
    pattern: Pattern[str] = field(repr=False, compare=False)
    confidence: float = 0.8
    keywords: tuple = ()
    require_context: bool = False
    context_radius: int = 120
    min_entropy: Optional[float] = None
    allowlist_patterns: Tuple[Pattern[str], ...] = field(
        default=(), repr=False, compare=False
    )
    stopwords: tuple = ()


@dataclass(frozen=True)
class Page:
    id: str
    title: str
    space_key: str
    version: int
    content: str = field(repr=False)
    web_url: Optional[str] = None
    attachment_id: Optional[str] = None
    attachment_name: Optional[str] = None
    comment_id: Optional[str] = None


@dataclass(frozen=True)
class Finding:
    rule_id: str
    rule_name: str
    severity: Severity
    confidence: float
    fingerprint: str
    page_id: str
    page_title: str
    space_key: str
    version: int
    location: str
    page_url: Optional[str] = None
    attachment_id: Optional[str] = None
    attachment_name: Optional[str] = None
    comment_id: Optional[str] = None
    matched_versions: Tuple[int, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "fingerprint": self.fingerprint,
            "page": {
                "id": self.page_id,
                "title": self.page_title,
                "space_key": self.space_key,
                "version": self.version,
            },
            "location": self.location,
            "matched_versions": list(self.matched_versions or (self.version,)),
            "source": {"type": "page"},
        }
        if self.page_url:
            result["page"]["url"] = self.page_url
        if self.comment_id:
            result["source"] = {
                "type": "comment",
                "comment": {"id": self.comment_id},
            }
        elif self.attachment_id:
            result["source"] = {
                "type": "attachment",
                "attachment": {
                    "id": self.attachment_id,
                    "name": self.attachment_name or self.attachment_id,
                },
            }
        return result


@dataclass(frozen=True)
class ScanError:
    scope: str
    message: str

    def to_dict(self) -> Dict[str, str]:
        return {"scope": self.scope, "message": self.message}


@dataclass
class ScanResult:
    spaces_discovered: int = 0
    spaces_scanned: int = 0
    pages_scanned: int = 0
    versions_scanned: int = 0
    historical_versions_scanned: int = 0
    comments_discovered: int = 0
    comments_scanned: int = 0
    attachments_discovered: int = 0
    attachments_scanned: int = 0
    attachments_skipped: int = 0
    attachment_bytes_scanned: int = 0
    findings_suppressed: int = 0
    findings: List[Finding] = field(default_factory=list)
    errors: List[ScanError] = field(default_factory=list)
    truncated: bool = False

    def counts_by_severity(self) -> Dict[str, int]:
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scanned": {
                "spaces_discovered": self.spaces_discovered,
                "spaces": self.spaces_scanned,
                "pages": self.pages_scanned,
                "versions": self.versions_scanned,
                "historical_versions": self.historical_versions_scanned,
                "comments_discovered": self.comments_discovered,
                "comments": self.comments_scanned,
                "attachments_discovered": self.attachments_discovered,
                "attachments": self.attachments_scanned,
                "attachments_skipped": self.attachments_skipped,
                "attachment_bytes": self.attachment_bytes_scanned,
            },
            "truncated": self.truncated,
            "finding_counts": self.counts_by_severity(),
            "baseline": {"suppressed_findings": self.findings_suppressed},
            "findings": [finding.to_dict() for finding in self.findings],
            "errors": [error.to_dict() for error in self.errors],
        }
