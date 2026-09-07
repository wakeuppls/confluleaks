import json
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, TextIO, Tuple

from scanner import PRODUCT_NAME
from scanner.confluence import ConfluenceError


class PreflightValidationError(ValueError):
    """A Confluence response does not match the REST API v1 shape."""


@dataclass(frozen=True)
class PreflightCheck:
    name: str
    status: str
    message: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "name": self.name,
            "status": self.status,
            "message": self.message,
        }


@dataclass
class PreflightResult:
    checks: List[PreflightCheck] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(check.status != "fail" for check in self.checks)

    def add(self, name: str, status: str, message: str) -> None:
        if status not in {"pass", "warn", "fail"}:
            raise ValueError(f"invalid preflight status: {status}")
        self.checks.append(PreflightCheck(name, status, message))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "preflight": {
                "ok": self.ok,
                "checks": [check.to_dict() for check in self.checks],
            }
        }


class PreflightChecker:
    def __init__(
        self,
        confluence_client,
        space_keys: Iterable[str] = (),
        check_history: bool = False,
        check_comments: bool = False,
        check_attachments: bool = False,
    ) -> None:
        self.confluence = confluence_client
        self.space_keys = tuple(dict.fromkeys(key for key in space_keys if key))
        self.check_history = check_history
        self.check_comments = check_comments
        self.check_attachments = check_attachments

    def run(self) -> PreflightResult:
        result = PreflightResult()
        try:
            spaces_payload = self.confluence.get_spaces(limit=1)
            visible_spaces = self._collection(spaces_payload, "spaces")
        except ConfluenceError as error:
            result.add("rest_api", "fail", self._request_failure(error))
            return result
        except PreflightValidationError as error:
            result.add("rest_api", "fail", str(error))
            return result

        result.add(
            "rest_api",
            "pass",
            "authentication succeeded and REST API v1 returned a valid collection",
        )

        target_spaces = []
        if self.space_keys:
            for space_key in self.space_keys:
                verified_key = self._check_space(space_key, result)
                if verified_key:
                    target_spaces.append(verified_key)
        elif visible_spaces:
            try:
                target_spaces.append(self._space_key(visible_spaces[0]))
            except PreflightValidationError as error:
                result.add("spaces", "fail", str(error))
        else:
            result.add(
                "spaces",
                "warn",
                "no visible spaces were returned; page capabilities were not checked",
            )

        for space_key in target_spaces:
            self._check_space_capabilities(space_key, result)
        return result

    def _check_space(self, space_key: str, result: PreflightResult) -> str:
        name = f"space:{space_key}"
        try:
            space = self.confluence.get_space(space_key)
            returned_key = self._space_key(space)
        except ConfluenceError as error:
            result.add(name, "fail", self._request_failure(error))
            return ""
        except PreflightValidationError as error:
            result.add(name, "fail", str(error))
            return ""

        if returned_key.casefold() != space_key.casefold():
            result.add(
                name,
                "fail",
                "Confluence returned a different space than requested",
            )
            return ""

        result.add(name, "pass", "space is visible to the configured account")
        return returned_key

    def _check_space_capabilities(
        self,
        space_key: str,
        result: PreflightResult,
    ) -> None:
        name = f"pages:{space_key}"
        try:
            pages_payload = self.confluence.get_pages(limit=1, space_key=space_key)
            pages = self._collection(pages_payload, "pages")
        except ConfluenceError as error:
            result.add(name, "fail", self._request_failure(error))
            return
        except PreflightValidationError as error:
            result.add(name, "fail", str(error))
            return

        if not pages:
            result.add(
                name,
                "pass",
                "page endpoint is accessible; no page was returned",
            )
            if self.check_history or self.check_comments or self.check_attachments:
                result.add(
                    f"sample:{space_key}",
                    "warn",
                    "optional capabilities need a visible page and were not checked",
                )
            return

        try:
            page_id, version = self._page_identity(pages[0])
        except PreflightValidationError as error:
            result.add(name, "fail", str(error))
            return
        result.add(
            name,
            "pass",
            "page endpoint returned the expected body.storage and version fields",
        )

        if self.check_comments:
            self._check_comments(page_id, space_key, result)
        if self.check_attachments:
            self._check_attachments(page_id, space_key, result)
        if self.check_history:
            self._check_history(page_id, version, space_key, result)

    def _check_comments(
        self,
        page_id: str,
        space_key: str,
        result: PreflightResult,
    ) -> None:
        name = f"comments:{space_key}"
        try:
            payload = self.confluence.get_comments(page_id, limit=1)
            comments = self._collection(payload, "comments")
            if comments:
                self._comment_identity(comments[0])
        except ConfluenceError as error:
            result.add(name, "fail", self._request_failure(error))
            return
        except PreflightValidationError as error:
            result.add(name, "fail", str(error))
            return
        result.add(name, "pass", "comment endpoint returned the expected shape")

    def _check_attachments(
        self,
        page_id: str,
        space_key: str,
        result: PreflightResult,
    ) -> None:
        name = f"attachments:{space_key}"
        try:
            payload = self.confluence.get_attachments(page_id, limit=1)
            attachments = self._collection(payload, "attachments")
            if attachments:
                self._content_id(attachments[0], "attachment")
        except ConfluenceError as error:
            result.add(name, "fail", self._request_failure(error))
            return
        except PreflightValidationError as error:
            result.add(name, "fail", str(error))
            return
        result.add(name, "pass", "attachment endpoint returned the expected shape")

    def _check_history(
        self,
        page_id: str,
        version: int,
        space_key: str,
        result: PreflightResult,
    ) -> None:
        name = f"history:{space_key}"
        if version <= 1:
            result.add(
                name,
                "warn",
                "sample page has no previous version; history was not checked",
            )
            return
        try:
            historical_page = self.confluence.get_page_version(page_id, version - 1)
            self._page_identity(historical_page)
        except ConfluenceError as error:
            if error.status_code == 404:
                result.add(
                    name,
                    "warn",
                    "previous sample version was unavailable; history was not verified",
                )
                return
            result.add(name, "fail", self._request_failure(error))
            return
        except PreflightValidationError as error:
            result.add(name, "fail", str(error))
            return
        result.add(name, "pass", "historical page endpoint returned the expected shape")

    @staticmethod
    def _collection(payload: Dict[str, Any], label: str) -> List[Any]:
        results = payload.get("results")
        if not isinstance(results, list):
            raise PreflightValidationError(
                f"REST API v1 {label} response is missing a results list"
            )
        return results

    @staticmethod
    def _space_key(space: Any) -> str:
        if not isinstance(space, dict):
            raise PreflightValidationError("space response must be an object")
        key = space.get("key")
        if not isinstance(key, str) or not key:
            raise PreflightValidationError("space response is missing a string key")
        return key

    @classmethod
    def _page_identity(cls, page: Any) -> Tuple[str, int]:
        page_id = cls._content_id(page, "page")
        try:
            storage_value = page["body"]["storage"]["value"]
            version = page["version"]["number"]
        except (KeyError, TypeError) as error:
            raise PreflightValidationError(
                "page response is missing body.storage or version fields"
            ) from error
        if not isinstance(storage_value, str):
            raise PreflightValidationError("page body.storage.value must be a string")
        if type(version) is not int or version < 1:
            raise PreflightValidationError(
                "page version.number must be a positive integer"
            )
        return page_id, version

    @classmethod
    def _comment_identity(cls, comment: Any) -> str:
        comment_id = cls._content_id(comment, "comment")
        try:
            storage_value = comment["body"]["storage"]["value"]
        except (KeyError, TypeError) as error:
            raise PreflightValidationError(
                "comment response is missing body.storage.value"
            ) from error
        if not isinstance(storage_value, str):
            raise PreflightValidationError(
                "comment body.storage.value must be a string"
            )
        return comment_id

    @staticmethod
    def _content_id(content: Any, label: str) -> str:
        if not isinstance(content, dict):
            raise PreflightValidationError(f"{label} response must be an object")
        content_id = content.get("id")
        if content_id is None or not str(content_id).strip():
            raise PreflightValidationError(f"{label} response is missing an id")
        return str(content_id)

    @staticmethod
    def _request_failure(error: ConfluenceError) -> str:
        if error.status_code == 401:
            return "authentication was rejected by Confluence (HTTP 401)"
        if error.status_code == 403:
            return "the configured account lacks permission (HTTP 403)"
        if error.status_code == 404:
            return "the requested REST resource was not found (HTTP 404)"
        return str(error)


def write_text_preflight(result: PreflightResult, stream: TextIO) -> None:
    status = "PASS" if result.ok else "FAIL"
    stream.write(f"{PRODUCT_NAME} preflight: {status}\n\n")
    for check in result.checks:
        stream.write(
            f"[{check.status.upper():<4}] {check.name}: {check.message}\n"
        )


def write_json_preflight(result: PreflightResult, stream: TextIO) -> None:
    json.dump(result.to_dict(), stream, indent=2, ensure_ascii=False)
    stream.write("\n")
