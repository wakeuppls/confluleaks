import json
import logging
import math
import time
from pathlib import Path
from typing import Any, Dict, Iterator, Optional
from urllib.parse import quote, urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from scanner import __version__
from scanner.auth import ConfluenceAuth
from scanner.logging_config import log_event


LOGGER = logging.getLogger("confluleaks.http")


class ConfluenceError(RuntimeError):
    """A Confluence request failed without exposing response content."""

    def __init__(self, message: str, status_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class AttachmentTooLargeError(RuntimeError):
    """An attachment exceeded the configured in-memory download limit."""


class ResponseTooLargeError(ConfluenceError):
    """A REST response exceeded the configured in-memory limit."""


class ConfluenceClient:
    def __init__(
        self,
        base_url: str,
        token: Optional[str] = None,
        timeout: float = 20.0,
        page_size: int = 50,
        retries: int = 3,
        backoff: float = 0.5,
        request_delay: float = 0.0,
        max_response_bytes: int = 16 * 1024 * 1024,
        auth: Optional[ConfluenceAuth] = None,
        ca_bundle: Optional[Path] = None,
    ) -> None:
        if auth is not None and token is not None:
            raise ValueError("pass either auth or token, not both")
        if auth is None:
            if token is None:
                raise ValueError("authentication configuration is required")
            auth = ConfluenceAuth.bearer(token)
        self.base_url = self._validated_base_url(base_url)
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be a positive finite number")
        self.timeout = timeout
        self.page_size = max(1, min(200, page_size))
        if not math.isfinite(request_delay) or request_delay < 0:
            raise ValueError("request_delay must be a finite non-negative number")
        self.request_delay = request_delay
        if retries < 0:
            raise ValueError("retries must not be negative")
        if not math.isfinite(backoff) or backoff < 0:
            raise ValueError("backoff must be a finite non-negative number")
        if max_response_bytes < 1:
            raise ValueError("max_response_bytes must be greater than zero")
        self.max_response_bytes = max_response_bytes
        self.ca_bundle = self._validated_ca_bundle(ca_bundle)
        self._last_request_at: Optional[float] = None
        self.session = requests.Session()
        if self.ca_bundle is not None:
            self.session.verify = str(self.ca_bundle)
        self.session.headers.update(
            {
                "Accept": "application/json",
                "User-Agent": f"confluleaks/{__version__}",
            }
        )
        auth.apply(self.session)
        retry_policy = Retry(
            total=retries,
            connect=retries,
            read=retries,
            status=retries,
            allowed_methods=frozenset({"GET"}),
            status_forcelist=(429, 500, 502, 503, 504),
            backoff_factor=backoff,
            respect_retry_after_header=True,
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry_policy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def close(self) -> None:
        self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    def get_spaces(self, start: int = 0, limit: Optional[int] = None) -> Dict[str, Any]:
        return self._get(
            "/rest/api/space",
            params={"start": start, "limit": limit or self.page_size},
        )

    def get_current_user(self) -> Dict[str, Any]:
        return self._get("/rest/api/user/current")

    def iter_spaces(self) -> Iterator[Dict[str, Any]]:
        yield from self._iterate("/rest/api/space")

    def get_space(self, space_key: str) -> Dict[str, Any]:
        encoded_key = quote(space_key, safe="")
        return self._get(f"/rest/api/space/{encoded_key}")

    def get_pages(
        self,
        start: int = 0,
        limit: Optional[int] = None,
        space_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {
            "type": "page",
            "status": "current",
            "expand": "body.storage,version,space",
            "start": start,
            "limit": limit or self.page_size,
        }
        if space_key:
            params["spaceKey"] = space_key
        return self._get("/rest/api/content", params=params)

    def iter_pages(self, space_key: Optional[str] = None) -> Iterator[Dict[str, Any]]:
        params: Dict[str, Any] = {
            "type": "page",
            "status": "current",
            "expand": "body.storage,version,space",
        }
        if space_key:
            params["spaceKey"] = space_key
        yield from self._iterate("/rest/api/content", params)

    def get_page(self, page_id: str) -> Dict[str, Any]:
        encoded_page_id = quote(page_id, safe="")
        return self._get(
            f"/rest/api/content/{encoded_page_id}",
            params={"expand": "body.storage,version,space"},
        )

    def get_page_version(self, page_id: str, version: int) -> Dict[str, Any]:
        """Fetch one historical page version through the stable content endpoint."""
        encoded_page_id = quote(page_id, safe="")
        return self._get(
            f"/rest/api/content/{encoded_page_id}",
            params={
                "status": "historical",
                "version": version,
                "expand": "body.storage,version,space",
            },
        )

    def iter_page_history(
        self,
        page_id: str,
        current_version: int,
        limit: Optional[int] = None,
    ) -> Iterator[Dict[str, Any]]:
        """Yield historical versions, newest first, skipping deleted version gaps."""
        versions = range(current_version - 1, 0, -1)
        if limit is not None:
            versions = versions[: max(0, limit)]

        for version in versions:
            try:
                yield self.get_page_version(page_id, version)
            except ConfluenceError as error:
                if error.status_code == 404:
                    continue
                raise

    def iter_attachments(self, page_id: str) -> Iterator[Dict[str, Any]]:
        encoded_page_id = quote(page_id, safe="")
        endpoint = f"/rest/api/content/{encoded_page_id}/child/attachment"
        yield from self._iterate(
            endpoint,
            {"expand": "version,metadata,extensions"},
        )

    def get_attachments(
        self,
        page_id: str,
        start: int = 0,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        encoded_page_id = quote(page_id, safe="")
        return self._get(
            f"/rest/api/content/{encoded_page_id}/child/attachment",
            params={
                "expand": "version,metadata,extensions",
                "start": start,
                "limit": limit or self.page_size,
            },
        )

    def iter_comments(self, page_id: str) -> Iterator[Dict[str, Any]]:
        """Yield current comments visible to the authenticated user."""
        encoded_page_id = quote(page_id, safe="")
        yield from self._iterate(
            f"/rest/api/content/{encoded_page_id}/child/comment",
            {
                "expand": "body.storage,version",
                "location": ("footer", "inline", "resolved"),
            },
        )

    def get_comments(
        self,
        page_id: str,
        start: int = 0,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        encoded_page_id = quote(page_id, safe="")
        return self._get(
            f"/rest/api/content/{encoded_page_id}/child/comment",
            params={
                "expand": "body.storage,version",
                "location": ("footer", "inline", "resolved"),
                "start": start,
                "limit": limit or self.page_size,
            },
        )

    def download_attachment(
        self,
        page_id: str,
        attachment: Dict[str, Any],
        max_bytes: int,
    ) -> bytes:
        if max_bytes < 1:
            raise ValueError("max_bytes must be greater than zero")

        raw_attachment_id = attachment.get("id")
        attachment_id = (
            str(raw_attachment_id).strip() if raw_attachment_id is not None else ""
        )
        links = attachment.get("_links")
        if not isinstance(links, dict):
            links = {}
        download_link = links.get("download")
        if download_link is not None and not isinstance(download_link, str):
            raise ConfluenceError("attachment download link must be a string")
        if download_link:
            endpoint = download_link
        elif attachment_id:
            encoded_page_id = quote(page_id, safe="")
            encoded_attachment_id = quote(attachment_id, safe="")
            endpoint = (
                f"/rest/api/content/{encoded_page_id}/child/attachment/"
                f"{encoded_attachment_id}/download"
            )
        else:
            raise ConfluenceError("attachment response is missing an id")

        url = self.absolute_url(endpoint)
        if not self._same_origin(url):
            raise ConfluenceError("refusing a cross-origin attachment download URL")
        started_at = self._log_request_start(url, attachment=True)
        try:
            self._wait_before_request()
            with self.session.get(
                url,
                timeout=self.timeout,
                stream=True,
                headers={"Accept": "*/*"},
                verify=self.session.verify,
            ) as response:
                response.raise_for_status()
                declared_size = response.headers.get("Content-Length")
                if declared_size is not None:
                    try:
                        if int(declared_size) > max_bytes:
                            raise AttachmentTooLargeError(
                                "attachment exceeds the configured size limit"
                            )
                    except ValueError:
                        pass

                chunks = []
                downloaded = 0
                for chunk in response.iter_content(chunk_size=64 * 1024):
                    if not chunk:
                        continue
                    downloaded += len(chunk)
                    if downloaded > max_bytes:
                        raise AttachmentTooLargeError(
                            "attachment exceeds the configured size limit"
                        )
                    chunks.append(chunk)
                content = b"".join(chunks)
                self._log_request_success(
                    url,
                    response,
                    len(content),
                    started_at,
                    attachment=True,
                )
                return content
        except AttachmentTooLargeError as error:
            self._log_request_failure(url, error, started_at, attachment=True)
            raise
        except requests.RequestException as error:
            wrapped = self._request_error(error, url, attachment=True)
            self._log_request_failure(url, wrapped, started_at, attachment=True)
            raise wrapped from error

    def _same_origin(self, url: str) -> bool:
        expected = urlsplit(self.base_url)
        actual = urlsplit(url)
        if actual.username or actual.password:
            return False
        try:
            expected_port = expected.port
            actual_port = actual.port
        except ValueError:
            return False

        if expected_port is None:
            expected_port = 443 if expected.scheme.casefold() == "https" else 80
        if actual_port is None:
            actual_port = 443 if actual.scheme.casefold() == "https" else 80
        return (
            actual.scheme.casefold(),
            actual.hostname,
            actual_port,
        ) == (
            expected.scheme.casefold(),
            expected.hostname,
            expected_port,
        )

    def absolute_url(self, relative_url: str) -> str:
        if relative_url.startswith(("http://", "https://")):
            return relative_url
        return f"{self.base_url}/{relative_url.lstrip('/')}"

    def _iterate(
        self, endpoint: str, params: Optional[Dict[str, Any]] = None
    ) -> Iterator[Dict[str, Any]]:
        start = 0
        while True:
            page_params = dict(params or {})
            page_params.update({"start": start, "limit": self.page_size})
            payload = self._get(endpoint, params=page_params)
            results = payload.get("results", [])
            if not isinstance(results, list):
                raise ConfluenceError(f"invalid paginated response from {endpoint}")

            for item in results:
                if not isinstance(item, dict):
                    raise ConfluenceError(
                        f"invalid paginated item from {endpoint}"
                    )
                yield item

            links = payload.get("_links", {})
            if not isinstance(links, dict):
                raise ConfluenceError(f"invalid pagination links from {endpoint}")
            next_link = links.get("next")
            if not next_link or not results:
                break
            start += len(results)

    def _get(
        self, endpoint: str, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        url = self.absolute_url(endpoint)
        request_target = self._request_target(url, params)
        started_at = self._log_request_start(request_target)
        try:
            self._wait_before_request()
            with self.session.get(
                url,
                params=params,
                timeout=self.timeout,
                stream=True,
                verify=self.session.verify,
            ) as response:
                response.raise_for_status()
                declared_size = response.headers.get("Content-Length")
                if declared_size is not None:
                    try:
                        if int(declared_size) > self.max_response_bytes:
                            raise ResponseTooLargeError(
                                "Confluence response exceeds the configured "
                                f"size limit: {request_target}"
                            )
                    except ValueError:
                        pass

                chunks = []
                downloaded = 0
                for chunk in response.iter_content(chunk_size=64 * 1024):
                    if not chunk:
                        continue
                    downloaded += len(chunk)
                    if downloaded > self.max_response_bytes:
                        raise ResponseTooLargeError(
                            "Confluence response exceeds the configured "
                            f"size limit: {request_target}"
                        )
                    chunks.append(chunk)
                payload = json.loads(b"".join(chunks))
                self._log_request_success(
                    request_target,
                    response,
                    downloaded,
                    started_at,
                )
        except ResponseTooLargeError as error:
            self._log_request_failure(request_target, error, started_at)
            raise
        except requests.RequestException as error:
            wrapped = self._request_error(error, request_target)
            self._log_request_failure(request_target, wrapped, started_at)
            raise wrapped from error
        except ValueError as error:
            wrapped = ConfluenceError(
                f"Confluence returned invalid JSON: {request_target}"
            )
            self._log_request_failure(request_target, wrapped, started_at)
            raise wrapped from error

        if not isinstance(payload, dict):
            error = ConfluenceError(
                f"Confluence returned an invalid response: {request_target}"
            )
            self._log_request_failure(request_target, error, started_at)
            raise error
        return payload

    def _log_request_start(self, request_target: str, attachment: bool = False) -> float:
        started_at = time.monotonic()
        log_event(
            LOGGER,
            logging.DEBUG,
            "http.request.started",
            method="GET",
            target=request_target,
            resource="attachment" if attachment else "rest_api",
            timeout_seconds=self.timeout,
        )
        return started_at

    @staticmethod
    def _log_request_success(
        request_target: str,
        response,
        response_bytes: int,
        started_at: float,
        attachment: bool = False,
    ) -> None:
        retry_state = getattr(getattr(response, "raw", None), "retries", None)
        retry_history = getattr(retry_state, "history", ())
        attempts = 1 + len(retry_history) if retry_history is not None else 1
        log_event(
            LOGGER,
            logging.DEBUG,
            "http.request.finished",
            method="GET",
            target=request_target,
            resource="attachment" if attachment else "rest_api",
            status=getattr(response, "status_code", None),
            response_bytes=response_bytes,
            attempts=attempts,
            elapsed_ms=round((time.monotonic() - started_at) * 1_000, 3),
        )

    @staticmethod
    def _log_request_failure(
        request_target: str,
        error: Exception,
        started_at: float,
        attachment: bool = False,
    ) -> None:
        log_event(
            LOGGER,
            logging.WARNING,
            "http.request.failed",
            method="GET",
            target=request_target,
            resource="attachment" if attachment else "rest_api",
            error_type=type(error).__name__,
            error=str(error),
            elapsed_ms=round((time.monotonic() - started_at) * 1_000, 3),
        )

    def _request_error(
        self,
        error: requests.RequestException,
        request_target: str,
        attachment: bool = False,
    ) -> ConfluenceError:
        resource = "attachment " if attachment else ""
        if isinstance(error, requests.exceptions.SSLError):
            return ConfluenceError(
                f"Confluence {resource}TLS certificate verification failed: "
                f"{request_target}"
            )
        if isinstance(error, requests.exceptions.Timeout):
            return ConfluenceError(
                f"Confluence {resource}request timed out "
                f"(per-request timeout {self.timeout:g}s): {request_target}"
            )
        if isinstance(error, requests.exceptions.TooManyRedirects):
            return ConfluenceError(
                f"Confluence {resource}request exceeded the redirect limit: "
                f"{request_target}"
            )
        if isinstance(error, requests.exceptions.ConnectionError):
            return ConfluenceError(
                f"Confluence {resource}connection failed after retries: "
                f"{request_target}"
            )
        if isinstance(error, requests.exceptions.ChunkedEncodingError):
            return ConfluenceError(
                f"Confluence {resource}response stream was interrupted: "
                f"{request_target}"
            )

        status = getattr(error.response, "status_code", None)
        suffix = f" (HTTP {status})" if status else ""
        return ConfluenceError(
            f"Confluence {resource}request failed{suffix}: {request_target}",
            status_code=status,
        )

    @staticmethod
    def _request_target(
        url: str,
        params: Optional[Dict[str, Any]],
    ) -> str:
        if not params:
            return url
        labels = {
            "spaceKey": "space",
            "start": "start",
            "limit": "limit",
            "status": "status",
            "version": "version",
        }
        context = [
            f"{label}={params[key]}"
            for key, label in labels.items()
            if key in params and not isinstance(params[key], (dict, list, tuple))
        ]
        return f"{url} ({', '.join(context)})" if context else url

    @staticmethod
    def _validated_ca_bundle(ca_bundle: Optional[Path]) -> Optional[Path]:
        if ca_bundle is None:
            return None
        path = Path(ca_bundle).expanduser()
        try:
            if not path.is_file() or path.stat().st_size == 0:
                raise ValueError
            with path.open("rb") as stream:
                stream.read(1)
        except (OSError, ValueError) as error:
            raise ValueError(
                f"CA bundle must be a readable non-empty file: {path}"
            ) from error
        return path

    def _wait_before_request(self) -> None:
        if self._last_request_at is not None and self.request_delay:
            elapsed = time.monotonic() - self._last_request_at
            remaining = self.request_delay - elapsed
            if remaining > 0:
                time.sleep(remaining)
        self._last_request_at = time.monotonic()

    @staticmethod
    def _validated_base_url(base_url: str) -> str:
        if not isinstance(base_url, str) or not base_url.strip():
            raise ValueError("Confluence base URL must be a non-empty string")
        normalized = base_url.strip().rstrip("/")
        parsed = urlsplit(normalized)
        if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Confluence base URL must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password:
            raise ValueError("Confluence base URL must not contain credentials")
        if parsed.query or parsed.fragment:
            raise ValueError("Confluence base URL must not contain a query or fragment")
        try:
            parsed.port
        except ValueError as error:
            raise ValueError("Confluence base URL contains an invalid port") from error
        return normalized
