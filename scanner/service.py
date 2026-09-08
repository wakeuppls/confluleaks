import math
import time
from dataclasses import replace
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from scanner.attachments import (
    attachment_name,
    attachment_size,
    decode_text_attachment,
    is_text_attachment,
)
from scanner.confluence import (
    AttachmentTooLargeError,
    ConfluenceError,
    ResponseTooLargeError,
)
from scanner.detector import DetectionTimeoutError, Detector
from scanner.extractor import extract_text
from scanner.models import Finding, Page, ScanError, ScanResult


class ScanLimitReached(RuntimeError):
    """Internal control flow for a global scan limit."""


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
        include_comments: bool = False,
        include_attachments: bool = False,
        max_attachment_bytes: int = 5 * 1024 * 1024,
        max_document_bytes: int = 5 * 1024 * 1024,
        max_findings: int = 10_000,
        max_findings_per_document: int = 1_000,
        max_runtime_seconds: float = 3_600.0,
        clock: Optional[Callable[[], float]] = None,
        progress: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.confluence = confluence_client
        self.detector = detector
        self.include_history = include_history
        self.history_limit = history_limit
        self.include_space_keys = self._unique_keys(include_spaces)
        self.include_spaces = self._normalized_keys(self.include_space_keys)
        self.exclude_space_keys = self._unique_keys(exclude_spaces)
        self.exclude_spaces = self._normalized_keys(self.exclude_space_keys)
        self.include_personal_spaces = include_personal_spaces
        self.include_archived_spaces = include_archived_spaces
        self.max_pages = max_pages
        self.continue_on_error = continue_on_error
        self.include_comments = include_comments
        self.include_attachments = include_attachments
        if max_attachment_bytes < 1:
            raise ValueError("max_attachment_bytes must be greater than zero")
        self.max_attachment_bytes = max_attachment_bytes
        if max_document_bytes < 1:
            raise ValueError("max_document_bytes must be greater than zero")
        self.max_document_bytes = max_document_bytes
        if max_findings < 1:
            raise ValueError("max_findings must be greater than zero")
        self.max_findings = max_findings
        if max_findings_per_document < 1:
            raise ValueError("max_findings_per_document must be greater than zero")
        self.max_findings_per_document = max_findings_per_document
        if not math.isfinite(max_runtime_seconds) or max_runtime_seconds <= 0:
            raise ValueError("max_runtime_seconds must be a positive finite number")
        self.max_runtime_seconds = max_runtime_seconds
        self._clock = clock or time.monotonic
        self._progress = progress
        self._started_at = 0.0

    def scan(self) -> ScanResult:
        self._started_at = self._clock()
        result = ScanResult()
        try:
            return self._scan(result)
        except ScanLimitReached:
            return self._finalize(result)
        except ResponseTooLargeError as error:
            self._record_confluence_error(result, "scan", error)
            return self._finalize(result)

    def _scan(self, result: ScanResult) -> ScanResult:
        spaces = self._discover_spaces(result)
        selected_spaces = self._select_spaces(spaces)
        self._emit_progress(
            f"Spaces discovered: {result.spaces_discovered}; "
            f"selected: {len(selected_spaces)}"
        )

        for index, space in enumerate(selected_spaces, start=1):
            space_key = self._space_key(space)
            result.spaces_scanned += 1
            pages_before = result.pages_scanned
            errors_before = len(result.errors)
            self._emit_progress(
                f"Scanning space {space_key} ({index}/{len(selected_spaces)})"
            )
            try:
                pages = self.confluence.iter_pages(space_key=space_key)
                for raw_page in pages:
                    self._check_runtime(result)
                    result.pages_discovered += 1
                    if self.max_pages is not None and (
                        result.pages_discovered > self.max_pages
                    ):
                        result.mark_truncated("max_pages")
                        raise ScanLimitReached
                    self._scan_page(raw_page, result)
                    self._progress_checkpoint(
                        result,
                        space_key,
                        result.pages_discovered,
                    )
            except ConfluenceError as error:
                self._emit_progress(
                    f"Request failed in space {space_key} after "
                    f"{result.pages_scanned - pages_before} pages"
                )
                if not self.continue_on_error and not isinstance(
                    error, ResponseTooLargeError
                ):
                    raise
                self._record_confluence_error(result, f"space:{space_key}", error)
                if isinstance(error, ResponseTooLargeError):
                    if not self.continue_on_error:
                        raise ScanLimitReached
            error_suffix = (
                " with errors" if len(result.errors) > errors_before else ""
            )
            self._emit_progress(
                f"Finished space {space_key}{error_suffix}: "
                f"pages={result.pages_scanned - pages_before}; "
                f"total_pages={result.pages_scanned}"
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
        page_id = "unknown"
        try:
            page_id = self._content_id(raw_page, "page")
            storage_value = self._storage_value(raw_page)
            if not self._document_within_limit(
                storage_value,
                result,
                scope=f"page:{page_id}",
            ):
                return
            page = self._page_from_response(raw_page, storage_value)
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
        self._scan_document(page, result, scope=f"page:{page.id}")

        if self.include_history:
            try:
                historical_pages = self.confluence.iter_page_history(
                    page.id,
                    current_version=page.version,
                    limit=self.history_limit,
                )
                for raw_version in historical_pages:
                    self._check_runtime(result)
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
                        storage_value = self._storage_value(raw_version)
                        version = raw_version.get("version", {}).get(
                            "number", "unknown"
                        )
                        if not self._document_within_limit(
                            storage_value,
                            result,
                            scope=f"page:{page.id}:version:{version}",
                        ):
                            continue
                        historical_page = self._page_from_response(
                            raw_version,
                            storage_value,
                        )
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
                    self._scan_document(
                        historical_page,
                        result,
                        scope=f"page:{page.id}:version:{historical_page.version}",
                    )
                    self._progress_checkpoint(
                        result,
                        page.space_key,
                        result.historical_versions_scanned,
                    )
            except ConfluenceError as error:
                if not self.continue_on_error and not isinstance(
                    error, ResponseTooLargeError
                ):
                    raise
                self._record_confluence_error(
                    result,
                    f"page:{page.id}:history",
                    error,
                )
                if isinstance(error, ResponseTooLargeError):
                    if not self.continue_on_error:
                        raise ScanLimitReached

        if self.include_comments:
            self._scan_comments(page, result)

        if self.include_attachments:
            self._scan_attachments(page, result)

    def _scan_comments(self, page: Page, result: ScanResult) -> None:
        try:
            comments = self.confluence.iter_comments(page.id)
            for raw_comment in comments:
                self._check_runtime(result)
                result.comments_discovered += 1
                self._progress_checkpoint(
                    result,
                    page.space_key,
                    result.comments_discovered,
                )
                comment_id = "unknown"
                try:
                    if not isinstance(raw_comment, dict):
                        raise TypeError(
                            "Confluence comment response must be an object"
                        )
                    comment_id = self._content_id(raw_comment, "comment")
                    storage_value = raw_comment["body"]["storage"]["value"]
                    if not isinstance(storage_value, str):
                        raise TypeError("Confluence comment body must be a string")
                except (KeyError, TypeError, ValueError):
                    if not self.continue_on_error:
                        raise
                    result.errors.append(
                        ScanError(
                            scope=f"page:{page.id}:comment:{comment_id}",
                            message="invalid Confluence comment response",
                        )
                    )
                    continue

                if not self._document_within_limit(
                    storage_value,
                    result,
                    scope=f"page:{page.id}:comment:{comment_id}",
                ):
                    continue

                document = replace(
                    page,
                    content=extract_text(storage_value),
                    attachment_id=None,
                    attachment_name=None,
                    comment_id=comment_id,
                )
                result.comments_scanned += 1
                self._scan_document(
                    document,
                    result,
                    scope=f"page:{page.id}:comment:{comment_id}",
                )
        except ConfluenceError as error:
            if not self.continue_on_error and not isinstance(
                error, ResponseTooLargeError
            ):
                raise
            self._record_confluence_error(
                result,
                f"page:{page.id}:comments",
                error,
            )
            if isinstance(error, ResponseTooLargeError):
                if not self.continue_on_error:
                    raise ScanLimitReached

    def _scan_attachments(self, page: Page, result: ScanResult) -> None:
        try:
            attachments = self.confluence.iter_attachments(page.id)
            for raw_attachment in attachments:
                self._check_runtime(result)
                result.attachments_discovered += 1
                self._progress_checkpoint(
                    result,
                    page.space_key,
                    result.attachments_discovered,
                )
                if not isinstance(raw_attachment, dict):
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

                try:
                    attachment_id = self._content_id(
                        raw_attachment,
                        "attachment",
                    )
                except (KeyError, TypeError, ValueError):
                    result.attachments_skipped += 1
                    if self.continue_on_error:
                        result.errors.append(
                            ScanError(
                                scope=f"page:{page.id}:attachment:unknown",
                                message="invalid Confluence attachment response",
                            )
                        )
                        continue
                    raise
                if not is_text_attachment(raw_attachment):
                    result.attachments_skipped += 1
                    continue

                declared_size = attachment_size(raw_attachment)
                if (
                    declared_size is not None
                    and declared_size > self.max_attachment_bytes
                ):
                    self._record_oversized_attachment(
                        result,
                        scope=f"page:{page.id}:attachment:{attachment_id}",
                        size=declared_size,
                    )
                    continue

                try:
                    content = self.confluence.download_attachment(
                        page.id,
                        raw_attachment,
                        self.max_attachment_bytes,
                    )
                except AttachmentTooLargeError as error:
                    self._record_oversized_attachment(
                        result,
                        scope=f"page:{page.id}:attachment:{attachment_id}",
                        message=str(error),
                    )
                    continue
                except ConfluenceError as error:
                    result.attachments_skipped += 1
                    if not self.continue_on_error and not isinstance(
                        error, ResponseTooLargeError
                    ):
                        raise
                    self._record_confluence_error(
                        result,
                        f"page:{page.id}:attachment:{attachment_id}",
                        error,
                    )
                    if isinstance(error, ResponseTooLargeError):
                        if not self.continue_on_error:
                            raise ScanLimitReached
                    continue

                text = decode_text_attachment(content)
                if text is None:
                    result.attachments_skipped += 1
                    continue

                if not self._document_within_limit(
                    text,
                    result,
                    scope=f"page:{page.id}:attachment:{attachment_id}",
                ):
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
                self._scan_document(
                    document,
                    result,
                    scope=f"page:{page.id}:attachment:{attachment_id}",
                )
        except ConfluenceError as error:
            if not self.continue_on_error and not isinstance(
                error, ResponseTooLargeError
            ):
                raise
            self._record_confluence_error(
                result,
                f"page:{page.id}:attachments",
                error,
            )
            if isinstance(error, ResponseTooLargeError):
                if not self.continue_on_error:
                    raise ScanLimitReached

    def _finalize(self, result: ScanResult) -> ScanResult:
        result.findings = self._deduplicate(result.findings)
        result.findings.sort(
            key=lambda finding: (
                -finding.severity.rank,
                finding.space_key,
                finding.page_id,
                finding.comment_id or "",
                finding.attachment_id or "",
                finding.rule_id,
            )
        )
        status = "incomplete" if result.truncated or result.errors else "complete"
        self._emit_progress(
            f"Scan {status}: spaces={result.spaces_scanned}; "
            f"pages={result.pages_scanned}; findings={len(result.findings)}; "
            f"errors={len(result.errors)}"
        )
        return result

    def _scan_document(
        self,
        document: Page,
        result: ScanResult,
        scope: str,
    ) -> None:
        remaining = max(0, self.max_findings - len(result.findings))
        document_limit = min(self.max_findings_per_document, remaining)
        try:
            findings, omitted = self.detector.scan_bounded(
                document,
                max_findings=document_limit,
            )
        except DetectionTimeoutError as error:
            result.mark_truncated("regex_timeout")
            result.errors.append(ScanError(scope=scope, message=str(error)))
            return

        result.findings.extend(findings)
        if not omitted:
            return

        if remaining <= self.max_findings_per_document:
            result.mark_truncated("max_findings")
            result.errors.append(
                ScanError(
                    scope=scope,
                    message=(
                        "global finding limit reached; remaining content was not "
                        "scanned"
                    ),
                )
            )
            raise ScanLimitReached

        result.mark_truncated("max_findings_per_document")
        result.errors.append(
            ScanError(
                scope=scope,
                message="per-document finding limit reached; matches were omitted",
            )
        )

    def _document_within_limit(
        self,
        content: str,
        result: ScanResult,
        scope: str,
    ) -> bool:
        size = len(content.encode("utf-8"))
        if size <= self.max_document_bytes:
            return True
        result.documents_skipped_too_large += 1
        result.mark_truncated("document_size")
        result.errors.append(
            ScanError(
                scope=scope,
                message=(
                    f"content size {size} bytes exceeds the configured "
                    f"{self.max_document_bytes} byte limit"
                ),
            )
        )
        return False

    def _check_runtime(self, result: ScanResult) -> None:
        if self._clock() - self._started_at < self.max_runtime_seconds:
            return
        result.mark_truncated("max_runtime")
        result.errors.append(
            ScanError(
                scope="scan",
                message=(
                    "maximum scan runtime reached; remaining content was not scanned"
                ),
            )
        )
        raise ScanLimitReached

    def _record_oversized_attachment(
        self,
        result: ScanResult,
        scope: str,
        size: Optional[int] = None,
        message: Optional[str] = None,
    ) -> None:
        result.attachments_skipped += 1
        result.mark_truncated("attachment_size")
        detail = message or (
            f"attachment size {size} bytes exceeds the configured "
            f"{self.max_attachment_bytes} byte limit"
        )
        result.errors.append(ScanError(scope=scope, message=detail))

    @staticmethod
    def _record_confluence_error(
        result: ScanResult,
        scope: str,
        error: ConfluenceError,
    ) -> None:
        if isinstance(error, ResponseTooLargeError):
            result.mark_truncated("response_size")
        result.errors.append(ScanError(scope=scope, message=str(error)))

    def _discover_spaces(self, result: ScanResult) -> List[Dict[str, Any]]:
        if not self.include_space_keys:
            self._emit_progress("Discovering visible spaces")
            spaces = []
            for space in self.confluence.iter_spaces():
                self._check_runtime(result)
                self._space_key(space)
                spaces.append(space)
                result.spaces_discovered += 1
                if self._progress_due(result.spaces_discovered):
                    self._emit_progress(
                        f"Visible spaces discovered: {result.spaces_discovered}"
                    )
            return spaces

        self._emit_progress(
            f"Resolving {len(self.include_space_keys)} requested spaces"
        )
        spaces = []
        for requested_key in self.include_space_keys:
            self._check_runtime(result)
            scope = f"space:{requested_key.casefold()}"
            try:
                space = self.confluence.get_space(requested_key)
            except ConfluenceError as error:
                self._record_confluence_error(result, scope, error)
                continue

            try:
                returned_key = self._space_key(space)
            except (TypeError, ValueError):
                if not self.continue_on_error:
                    raise
                result.errors.append(
                    ScanError(
                        scope=scope,
                        message="invalid Confluence space response",
                    )
                )
                continue
            if returned_key.casefold() != requested_key.casefold():
                result.errors.append(
                    ScanError(
                        scope=scope,
                        message="requested space was not returned by Confluence",
                    )
                )
                continue

            spaces.append(space)
            result.spaces_discovered += 1
        return spaces

    def _progress_checkpoint(
        self,
        result: ScanResult,
        space_key: str,
        counter: int,
    ) -> None:
        if not self._progress_due(counter):
            return
        self._emit_progress(
            f"Progress in {space_key}: pages_seen={result.pages_discovered}; "
            f"historical_versions={result.historical_versions_scanned}; "
            f"comments_seen={result.comments_discovered}; "
            f"attachments_seen={result.attachments_discovered}; "
            f"candidate_findings={len(result.findings)}"
        )

    def _emit_progress(self, message: str) -> None:
        if self._progress is not None:
            self._progress(message)

    @staticmethod
    def _progress_due(counter: int) -> bool:
        return counter == 1 or counter % 25 == 0

    def _select_spaces(self, spaces: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        selected = []
        for space in spaces:
            key = self._space_key(space)
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
        return {key.strip().casefold() for key in keys if key.strip()}

    @staticmethod
    def _unique_keys(keys: Iterable[str]) -> Tuple[str, ...]:
        unique: Dict[str, str] = {}
        for key in keys:
            if not isinstance(key, str):
                raise ValueError("space keys must be strings")
            normalized = key.strip().casefold()
            if normalized:
                unique.setdefault(normalized, key.strip())
        return tuple(unique.values())

    @staticmethod
    def _space_key(space: Dict[str, Any]) -> str:
        if not isinstance(space, dict):
            raise TypeError("Confluence space response must be an object")
        key = space.get("key")
        if not isinstance(key, str) or not key.strip():
            raise ValueError("Confluence space key must be a non-empty string")
        return key.strip()

    @staticmethod
    def _content_id(content: Dict[str, Any], label: str) -> str:
        raw_id = content.get("id")
        if raw_id is None:
            raise ValueError(f"Confluence {label} id must not be null")
        content_id = str(raw_id).strip()
        if not content_id:
            raise ValueError(f"Confluence {label} id must not be empty")
        return content_id

    @staticmethod
    def _deduplicate(findings: Iterable[Finding]) -> List[Finding]:
        unique: Dict[Tuple[str, str, str, str, str], Finding] = {}
        for finding in findings:
            key = (
                finding.page_id,
                finding.comment_id or "",
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

    @staticmethod
    def _storage_value(raw_content: Dict[str, Any]) -> str:
        body = raw_content["body"]
        if not isinstance(body, dict):
            raise TypeError("Confluence content body must be an object")
        storage = body["storage"]
        if not isinstance(storage, dict):
            raise TypeError("Confluence storage body must be an object")
        value = storage["value"]
        if not isinstance(value, str):
            raise TypeError("Confluence storage body must be a string")
        return value

    def _page_from_response(
        self,
        raw_page: Dict[str, Any],
        storage_value: Optional[str] = None,
    ) -> Page:
        page_id = self._content_id(raw_page, "page")
        title = raw_page.get("title", page_id)
        if not isinstance(title, str):
            raise TypeError("Confluence page title must be a string")
        space = raw_page["space"]
        if not isinstance(space, dict):
            raise TypeError("Confluence page space must be an object")
        space_key = self._space_key(space)
        version_payload = raw_page["version"]
        if not isinstance(version_payload, dict):
            raise TypeError("Confluence page version must be an object")
        version = version_payload["number"]
        if type(version) is not int or version < 1:
            raise ValueError("Confluence page version must be a positive integer")
        links = raw_page.get("_links", {})
        if not isinstance(links, dict):
            raise TypeError("Confluence page links must be an object")
        relative_url = links.get("webui")
        if relative_url is not None and not isinstance(relative_url, str):
            raise TypeError("Confluence page web URL must be a string")
        if storage_value is None:
            storage_value = self._storage_value(raw_page)
        return Page(
            id=page_id,
            title=title,
            space_key=space_key,
            version=version,
            content=extract_text(storage_value),
            web_url=(
                self.confluence.absolute_url(relative_url)
                if relative_url
                else None
            ),
        )
