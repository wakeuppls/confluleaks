import time
from typing import Any, Dict, Iterator, Optional
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from scanner import __version__


class ConfluenceError(RuntimeError):
    """A Confluence request failed without exposing response content."""

    def __init__(self, message: str, status_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class AttachmentTooLargeError(RuntimeError):
    """An attachment exceeded the configured in-memory download limit."""


class ConfluenceClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        timeout: float = 20.0,
        page_size: int = 50,
        retries: int = 3,
        backoff: float = 0.5,
        request_delay: float = 0.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.page_size = max(1, min(200, page_size))
        self.request_delay = max(0.0, request_delay)
        self._last_request_at: Optional[float] = None
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "User-Agent": f"confluleaks/{__version__}",
            }
        )
        retry_policy = Retry(
            total=max(0, retries),
            connect=max(0, retries),
            read=max(0, retries),
            status=max(0, retries),
            allowed_methods=frozenset({"GET"}),
            status_forcelist=(429, 500, 502, 503, 504),
            backoff_factor=max(0.0, backoff),
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

    def iter_spaces(self) -> Iterator[Dict[str, Any]]:
        yield from self._iterate("/rest/api/space")

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
        return self._get(
            f"/rest/api/content/{page_id}",
            params={"expand": "body.storage,version,space"},
        )

    def get_page_version(self, page_id: str, version: int) -> Dict[str, Any]:
        """Fetch one historical page version through the stable content endpoint."""
        return self._get(
            f"/rest/api/content/{page_id}",
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
        yield from self._iterate(
            f"/rest/api/content/{page_id}/child/attachment",
            {"expand": "version,metadata,extensions"},
        )

    def download_attachment(
        self,
        page_id: str,
        attachment: Dict[str, Any],
        max_bytes: int,
    ) -> bytes:
        if max_bytes < 1:
            raise ValueError("max_bytes must be greater than zero")

        attachment_id = str(attachment.get("id", ""))
        links = attachment.get("_links")
        if not isinstance(links, dict):
            links = {}
        download_link = links.get("download")
        if download_link:
            endpoint = str(download_link)
        elif attachment_id:
            endpoint = (
                f"/rest/api/content/{page_id}/child/attachment/"
                f"{attachment_id}/download"
            )
        else:
            raise ConfluenceError("attachment response is missing an id")

        url = self.absolute_url(endpoint)
        if not self._same_origin(url):
            raise ConfluenceError("refusing a cross-origin attachment download URL")
        try:
            self._wait_before_request()
            with self.session.get(
                url,
                timeout=self.timeout,
                stream=True,
                headers={"Accept": "*/*"},
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
                return b"".join(chunks)
        except AttachmentTooLargeError:
            raise
        except requests.RequestException as error:
            status = getattr(error.response, "status_code", None)
            suffix = f" (HTTP {status})" if status else ""
            raise ConfluenceError(
                f"Confluence attachment request failed{suffix}: {url}",
                status_code=status,
            ) from error

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

            yield from results
            next_link = payload.get("_links", {}).get("next")
            if not next_link or not results:
                break
            start += len(results)

    def _get(
        self, endpoint: str, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        url = self.absolute_url(endpoint)
        try:
            self._wait_before_request()
            response = self.session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            payload = response.json()
        except requests.RequestException as error:
            status = getattr(error.response, "status_code", None)
            suffix = f" (HTTP {status})" if status else ""
            raise ConfluenceError(
                f"Confluence request failed{suffix}: {url}",
                status_code=status,
            ) from error
        except ValueError as error:
            raise ConfluenceError(f"Confluence returned invalid JSON: {url}") from error

        if not isinstance(payload, dict):
            raise ConfluenceError(f"Confluence returned an invalid response: {url}")
        return payload

    def _wait_before_request(self) -> None:
        if self._last_request_at is not None and self.request_delay:
            elapsed = time.monotonic() - self._last_request_at
            remaining = self.request_delay - elapsed
            if remaining > 0:
                time.sleep(remaining)
        self._last_request_at = time.monotonic()
