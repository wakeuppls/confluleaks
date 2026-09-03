from pathlib import PurePosixPath
from typing import Any, Dict, Optional


TEXT_EXTENSIONS = frozenset(
    {
        ".cfg",
        ".conf",
        ".csv",
        ".env",
        ".ini",
        ".js",
        ".json",
        ".log",
        ".md",
        ".properties",
        ".py",
        ".sh",
        ".sql",
        ".ts",
        ".txt",
        ".xml",
        ".yaml",
        ".yml",
    }
)

TEXT_MEDIA_TYPES = frozenset(
    {
        "application/ecmascript",
        "application/javascript",
        "application/json",
        "application/sql",
        "application/x-httpd-php",
        "application/x-javascript",
        "application/x-sh",
        "application/x-yaml",
        "application/xml",
        "application/yaml",
    }
)

GENERIC_MEDIA_TYPES = frozenset(
    {
        "",
        "application/octet-stream",
        "binary/octet-stream",
    }
)


def attachment_name(attachment: Dict[str, Any]) -> str:
    return str(attachment.get("title") or attachment.get("name") or "")


def attachment_media_type(attachment: Dict[str, Any]) -> str:
    metadata = attachment.get("metadata")
    extensions = attachment.get("extensions")
    if not isinstance(metadata, dict):
        metadata = {}
    if not isinstance(extensions, dict):
        extensions = {}
    value = (
        attachment.get("mediaType")
        or metadata.get("mediaType")
        or extensions.get("mediaType")
        or ""
    )
    return str(value).split(";", 1)[0].strip().casefold()


def attachment_size(attachment: Dict[str, Any]) -> Optional[int]:
    value = attachment.get("fileSize")
    if value is None:
        extensions = attachment.get("extensions")
        if isinstance(extensions, dict):
            value = extensions.get("fileSize")
    if value is None:
        return None
    try:
        size = int(value)
    except (TypeError, ValueError):
        return None
    return size if size >= 0 else None


def is_text_attachment(attachment: Dict[str, Any]) -> bool:
    """Accept known text formats while rejecting binary MIME types."""
    media_type = attachment_media_type(attachment)
    if media_type.startswith("text/") or media_type in TEXT_MEDIA_TYPES:
        return True
    if media_type not in GENERIC_MEDIA_TYPES:
        return False

    suffix = PurePosixPath(attachment_name(attachment)).suffix.casefold()
    return suffix in TEXT_EXTENSIONS


def decode_text_attachment(content: bytes) -> Optional[str]:
    """Decode a classified text attachment, rejecting binary-looking data."""
    if not content:
        return ""

    if content.startswith((b"\xff\xfe", b"\xfe\xff")):
        encoding = "utf-16"
    elif content.startswith(b"\xef\xbb\xbf"):
        encoding = "utf-8-sig"
    else:
        encoding = "utf-8"

    try:
        text = content.decode(encoding)
    except UnicodeDecodeError:
        return None

    if "\x00" in text:
        return None
    return text
