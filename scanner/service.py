from dataclasses import replace
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from scanner.attachments import (
    attachment_name,
    attachment_size,
    decode_text_attachment,
    is_text_attachment,
)
from scanner.confluence import AttachmentTooLargeError, ConfluenceError
from scanner.detector import Detector
from scanner.extractor import extract_text
from scanner.models import Finding, Page, ScanError, ScanResult


class SecretScanner:
    def __init__(
        self,
        confluence_client,
        detector: Detector,
        include_history: bool = False,
        history_limit: Optional[int] = None,
        include_spaces: Iterable[str] = (),
        exclude_spaces: Iterable[str] = (),
        include_personal_spaces: bool = False,
        include_archived_spaces: bool = False,
        max_pages: Optional[int] = None,
        continue_on_error: bool = False,
        include_attachments: bool = False,
        max_attachment_bytes: int = 5 * 1024 * 1024,
    ) -> None:
        self.confluence = confluence_client
        self.detector = detector
        self.include_history = include_history
        self.history_limit = history_limit
        self.include_spaces = self._normalized_keys(include_spaces)
        self.exclude_spaces = self._normalized_keys(exclude_spaces)
        self.include_personal_spaces = include_personal_spaces
        self.include_archived_spaces = include_archived_spaces
        self.max_pages = max_pages
        self.continue_on_error = continue_on_error
        self.include_attachments = include_attachments
        if max_attachment_bytes < 1:
            raise ValueError("max_attachment_bytes must be greater than zero")
        self.max_attachment_bytes = max_attachment_bytes

    def scan(self) -> ScanResult:
        spaces = list(self.confluence.iter_spaces())
        selected_spaces = self._select_spaces(spaces)
        result = ScanResult(spaces_discovered=len(spaces))

        discovered_keys = self._normalized_keys(
            str(space.get("key", "")) for space in spaces
        )
        for missing_key in sorted(self.include_spaces - discovered_keys):
            result.errors.append(
                ScanError(
                    scope=f"space:{missing_key}",
                    message="requested space was not returned by Confluence",
                )
            )

        for space in selected_spaces:
            space_key = str(space["key"])
            result.spaces_scanned += 1
            try:
                pages = self.confluence.iter_pages(space_key=space_key)
                for raw_page in pages:
                    if (
                        self.max_pages is not None
                        and result.pages_scanned >= self.max_pages
                    ):
                        result.truncated = True
                        return self._finalize(result)
                    self._scan_page(raw_page, result)
            except ConfluenceError as error:
                if not self.continue_on_error:
                    raise
                result.errors.append(
                    ScanError(scope=f"space:{space_key}", message=str(error))
                )

        return self._finalize(result)

    def _scan_page(self, raw_page: Dict[str, Any], result: ScanResult) -> None:
        if not isinstance(raw_page, dict):
            if not self.continue_on_error:
                raise TypeError("Confluence page response must be an object")
            result.errors.append(
                ScanError(
                    scope="page:unknown",
                    message="invalid Confluence page response",
                )
            )
            return
        page_id = str(raw_page.get("id", "unknown"))
        try:
            page = self._page_from_response(raw_page)
        except (KeyError, TypeError, ValueError):
            if not self.continue_on_error:
                raise
            result.errors.append(
                ScanError(
                    scope=f"page:{page_id}",
                    message="invalid Confluence page response",
                )
            )
            return

        result.pages_scanned += 1
        result.versions_scanned += 1
        result.findings.extend(self.detector.scan(page))

        if self.include_history:
            try:
                historical_pages = self.confluence.iter_page_history(
                    page.id,
                    current_version=page.version,
                    limit=self.history_limit,
                )
                for raw_version in historical_pages:
                    if not isinstance(raw_version, dict):
                        if not self.continue_on_error:
                            raise TypeError(
                                "Confluence historical page response must be an object"
                            )
                        result.errors.append(
                            ScanError(
                                scope=f"page:{page.id}:version:unknown",
                                message="invalid Confluence page response",
                            )
                        )
                        continue
                    try:
                        historical_page = self._page_from_response(raw_version)
                    except (KeyError, TypeError, ValueError):
                        if not self.continue_on_error:
                            raise
                        version = raw_version.get("version", {}).get(
                            "number", "unknown"
                        )
                        result.errors.append(
                            ScanError(
                                scope=f"page:{page.id}:version:{version}",
                                message="invalid Confluence page response",
                            )
                        )
                        continue
                    historical_page = replace(
                        historical_page,
                        title=page.title,
                        space_key=page.space_key,
                        web_url=page.web_url,
                    )
                    result.versions_scanned += 1
                    result.historical_versions_scanned += 1
                    result.findings.extend(self.detector.scan(historical_page))
            except ConfluenceError as error:
                if not self.continue_on_error:
                    raise
                result.errors.append(
                    ScanError(scope=f"page:{page.id}:history", message=str(error))
                )

        if self.include_attachments:
            self._scan_attachments(page, result)

    def _scan_attachments(self, page: Page, result: ScanResult) -> None:
        try:
            attachments = self.confluence.iter_attachments(page.id)
            for raw_attachment in attachments:
                if not isinstance(raw_attachment, dict):
                    result.attachments_discovered += 1
                    result.attachments_skipped += 1
                    if self.continue_on_error:
                        result.errors.append(
                            ScanError(
                                scope=f"page:{page.id}:attachment:unknown",
                                message="invalid Confluence attachment response",
                            )
                        )
                        continue
                    raise TypeError("Confluence attachment response must be an object")

                result.attachments_discovered += 1
                attachment_id = str(raw_attachment.get("id", "unknown"))
                if not is_text_attachment(raw_attachment):
                    result.attachments_skipped += 1
                    continue

                declared_size = attachment_size(raw_attachment)
                if (
                    declared_size is not None
                    and declared_size > self.max_attachment_bytes
                ):
                    result.attachments_skipped += 1
                    continue

                try:
                    content = self.confluence.download_attachment(
                        page.id,
                        raw_attachment,
                        self.max_attachment_bytes,
                    )
                except AttachmentTooLargeError:
                    result.attachments_skipped += 1
                    continue
                except ConfluenceError as error:
                    result.attachments_skipped += 1
                    if not self.continue_on_error:
                        raise
                    result.errors.append(
                        ScanError(
                            scope=f"page:{page.id}:attachment:{attachment_id}",
                            message=str(error),
                        )
                    )
                    continue

                text = decode_text_attachment(content)
                if text is None:
                    result.attachments_skipped += 1
                    continue

                document = replace(
                    page,
                    content=text,
                    attachment_id=attachment_id,
                    attachment_name=attachment_name(raw_attachment) or attachment_id,
                )
                result.attachments_scanned += 1
                result.attachment_bytes_scanned += len(content)
                result.findings.extend(self.detector.scan(document))
        except ConfluenceError as error:
            if not self.continue_on_error:
                raise
            result.errors.append(
                ScanError(scope=f"page:{page.id}:attachments", message=str(error))
            )

    def _finalize(self, result: ScanResult) -> ScanResult:
        result.findings = self._deduplicate(result.findings)
        result.findings.sort(
            key=lambda finding: (
                -finding.severity.rank,
                finding.space_key,
                finding.page_id,
                finding.attachment_id or "",
                finding.rule_id,
            )
        )
        return result

    def _select_spaces(self, spaces: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        selected = []
        for space in spaces:
            key = str(space.get("key", ""))
            normalized_key = key.casefold()
            explicitly_included = normalized_key in self.include_spaces

            if self.include_spaces and not explicitly_included:
                continue
            if normalized_key in self.exclude_spaces:
                continue
            if not explicitly_included:
                is_personal = (
                    str(space.get("type", "")).casefold() == "personal"
                    or key.startswith("~")
                )
                if is_personal and not self.include_personal_spaces:
                    continue
                if (
                    str(space.get("status", "current")).casefold() == "archived"
                    and not self.include_archived_spaces
                ):
                    continue
            selected.append(space)
        return selected

    @staticmethod
    def _normalized_keys(keys: Iterable[str]) -> Set[str]:
        return {key.casefold() for key in keys if key}

    @staticmethod
    def _deduplicate(findings: Iterable[Finding]) -> List[Finding]:
        unique: Dict[Tuple[str, str, str, str], Finding] = {}
        for finding in findings:
            key = (
                finding.page_id,
                finding.attachment_id or "",
                finding.rule_id,
                finding.fingerprint,
            )
            existing = unique.get(key)
            if existing is None:
                unique[key] = replace(
                    finding,
                    matched_versions=(finding.version,),
                )
                continue

            versions = tuple(
                sorted(
                    set(existing.matched_versions) | {finding.version},
                    reverse=True,
                )
            )
            unique[key] = replace(existing, matched_versions=versions)
        return list(unique.values())

    def _page_from_response(self, raw_page: Dict[str, Any]) -> Page:
        page_id = str(raw_page["id"])
        relative_url = raw_page.get("_links", {}).get("webui")
        return Page(
            id=page_id,
            title=str(raw_page.get("title", page_id)),
            space_key=str(raw_page.get("space", {}).get("key", "")),
            version=int(raw_page.get("version", {}).get("number", 1)),
            content=extract_text(
                str(raw_page.get("body", {}).get("storage", {}).get("value", ""))
            ),
            web_url=self.confluence.absolute_url(relative_url) if relative_url else None,
        )
