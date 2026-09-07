import hashlib
import math
from collections import Counter
from typing import Iterable, List, Optional, Tuple

from scanner.models import Finding, Page, Rule


class DetectionTimeoutError(RuntimeError):
    """A detection rule exceeded its configured execution budget."""

    def __init__(self, rule_id: str) -> None:
        super().__init__(f"detection rule timed out: {rule_id}")
        self.rule_id = rule_id


class Detector:
    def __init__(self, rules: Iterable[Rule], regex_timeout: float = 0.25) -> None:
        if not math.isfinite(regex_timeout) or regex_timeout <= 0:
            raise ValueError("regex_timeout must be a positive finite number")
        self.rules = tuple(rules)
        self.regex_timeout = regex_timeout

    def scan(self, page: Page) -> List[Finding]:
        findings, _ = self.scan_bounded(page)
        return findings

    def scan_bounded(
        self,
        page: Page,
        max_findings: Optional[int] = None,
    ) -> Tuple[List[Finding], bool]:
        """Return findings and whether additional matches were omitted."""
        if max_findings is not None and max_findings < 0:
            raise ValueError("max_findings must not be negative")
        findings = []
        for rule in self.rules:
            try:
                matches = self._finditer(rule.pattern, page.content)
                for match in matches:
                    secret, start = self._secret_and_start(match)
                    if self._is_allowlisted(rule, secret):
                        continue
                    if (
                        rule.min_entropy is not None
                        and self._entropy(secret) < rule.min_entropy
                    ):
                        continue

                    context = self._context(
                        page.content,
                        start,
                        len(secret),
                        rule.context_radius,
                    )
                    has_context = not rule.keywords or any(
                        keyword in context.lower() for keyword in rule.keywords
                    )
                    if rule.require_context and not has_context:
                        continue

                    if max_findings is not None and len(findings) >= max_findings:
                        return findings, True

                    confidence = rule.confidence
                    if rule.keywords and has_context:
                        confidence = min(1.0, confidence + 0.08)

                    findings.append(
                        Finding(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            confidence=round(confidence, 2),
                            fingerprint=self._fingerprint(rule.id, secret),
                            page_id=page.id,
                            page_title=page.title,
                            space_key=page.space_key,
                            version=page.version,
                            location=self._location(page.content, start),
                            page_url=page.web_url,
                            attachment_id=page.attachment_id,
                            attachment_name=page.attachment_name,
                            comment_id=page.comment_id,
                        )
                    )
            except TimeoutError as error:
                raise DetectionTimeoutError(rule.id) from error
        return findings, False

    def _finditer(self, pattern, content: str):
        try:
            return pattern.finditer(content, timeout=self.regex_timeout)
        except TypeError:
            return pattern.finditer(content)

    @staticmethod
    def _secret_and_start(match) -> Tuple[str, int]:
        secret_groups = (
            name
            for name in match.re.groupindex
            if name == "secret" or name.startswith("secret_")
        )
        for group_name in secret_groups:
            if match.group(group_name) is not None:
                return match.group(group_name), match.start(group_name)
        return match.group(0), match.start()

    @staticmethod
    def _context(content: str, start: int, length: int, radius: int) -> str:
        left = max(0, start - radius)
        right = min(len(content), start + length + radius)
        return content[left:right]

    def _is_allowlisted(self, rule: Rule, secret: str) -> bool:
        normalized = secret.lower()
        if any(stopword in normalized for stopword in rule.stopwords):
            return True
        for pattern in rule.allowlist_patterns:
            try:
                match = pattern.search(secret, timeout=self.regex_timeout)
            except TypeError:
                match = pattern.search(secret)
            if match:
                return True
        return False

    @staticmethod
    def _entropy(value: str) -> float:
        if not value:
            return 0.0
        length = len(value)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in Counter(value).values()
        )

    @staticmethod
    def _location(content: str, start: int) -> str:
        line = content.count("\n", 0, start) + 1
        previous_newline = content.rfind("\n", 0, start)
        column = start + 1 if previous_newline == -1 else start - previous_newline
        return f"line:{line}:column:{column}"

    @staticmethod
    def _fingerprint(rule_id: str, secret: str) -> str:
        material = f"{rule_id}\0{secret}".encode("utf-8")
        return hashlib.sha256(material).hexdigest()
