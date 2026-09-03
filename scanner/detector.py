import hashlib
import math
from collections import Counter
from typing import Iterable, List, Tuple

from scanner.models import Finding, Page, Rule


class Detector:
    def __init__(self, rules: Iterable[Rule]) -> None:
        self.rules = tuple(rules)

    def scan(self, page: Page) -> List[Finding]:
        findings = []
        for rule in self.rules:
            for match in rule.pattern.finditer(page.content):
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
                    )
                )
        return findings

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

    @staticmethod
    def _is_allowlisted(rule: Rule, secret: str) -> bool:
        normalized = secret.lower()
        if any(stopword in normalized for stopword in rule.stopwords):
            return True
        return any(pattern.search(secret) for pattern in rule.allowlist_patterns)

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
