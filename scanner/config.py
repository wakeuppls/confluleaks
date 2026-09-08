import argparse
import math
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence

import yaml


CONFIG_VERSION = 1
DEFAULT_CONFIG_NAME = "confluleaks.yaml"
CONFIG_ENVIRONMENT_VARIABLE = "CONFLULEAKS_CONFIG"


class ConfigurationError(ValueError):
    """A scanner configuration file is missing, unsafe, or invalid."""


@dataclass(frozen=True)
class Configuration:
    values: Dict[str, Any] = field(default_factory=dict)
    path: Optional[Path] = None


BOOLEAN_FIELDS = {
    "include_personal_spaces",
    "include_archived_spaces",
    "history",
    "comments",
    "attachments",
    "continue_on_error",
    "progress",
}
POSITIVE_INTEGER_FIELDS = {
    "page_size",
    "max_pages",
    "history_limit",
    "max_findings",
    "max_findings_per_document",
}
NONNEGATIVE_INTEGER_FIELDS = {"retries"}
POSITIVE_NUMBER_FIELDS = {
    "timeout",
    "max_attachment_size_mb",
    "max_response_size_mb",
    "max_document_size_mb",
    "regex_timeout",
    "max_runtime",
}
NONNEGATIVE_NUMBER_FIELDS = {"backoff", "request_delay"}
STRING_FIELDS = {"url"}
PATH_FIELDS = {"rules", "baseline", "ca_bundle", "log_file"}
LIST_FIELDS = {"spaces", "exclude_spaces"}
CHOICE_FIELDS = {
    "auth": {"bearer", "basic"},
    "format": {"text", "json", "sarif"},
    "fail_on": {"low", "medium", "high", "critical"},
    "log_level": {"debug", "info", "warning", "error"},
}
ALLOWED_FIELDS = (
    BOOLEAN_FIELDS
    | POSITIVE_INTEGER_FIELDS
    | NONNEGATIVE_INTEGER_FIELDS
    | POSITIVE_NUMBER_FIELDS
    | NONNEGATIVE_NUMBER_FIELDS
    | STRING_FIELDS
    | PATH_FIELDS
    | LIST_FIELDS
    | set(CHOICE_FIELDS)
)
FORBIDDEN_SECRET_FIELDS = {
    "token",
    "password",
    "api_token",
    "username",
}


def discover_config_path(
    argv: Sequence[str],
    environ: Optional[Mapping[str, str]] = None,
    cwd: Optional[Path] = None,
) -> Optional[Path]:
    locator = argparse.ArgumentParser(add_help=False)
    group = locator.add_mutually_exclusive_group()
    group.add_argument("--config", type=Path)
    group.add_argument("--no-config", action="store_true")
    known, _ = locator.parse_known_args(argv)

    if known.no_config:
        return None
    if known.config is not None:
        return known.config.expanduser()

    environment = environ if environ is not None else os.environ
    configured_path = environment.get(CONFIG_ENVIRONMENT_VARIABLE)
    if configured_path:
        return Path(configured_path).expanduser()

    directory = cwd if cwd is not None else Path.cwd()
    default_path = directory / DEFAULT_CONFIG_NAME
    return default_path if default_path.is_file() else None


def load_config(path: Optional[Path]) -> Configuration:
    if path is None:
        return Configuration()
    try:
        with path.open(encoding="utf-8") as stream:
            document = yaml.safe_load(stream)
    except OSError as error:
        raise ConfigurationError(f"cannot read configuration: {path}") from error
    except yaml.YAMLError as error:
        raise ConfigurationError(
            f"configuration is not valid YAML: {path}"
        ) from error

    if not isinstance(document, dict):
        raise ConfigurationError("configuration root must be an object")
    version = document.get("version")
    if type(version) is not int or version != CONFIG_VERSION:
        raise ConfigurationError(
            f"unsupported configuration version: expected {CONFIG_VERSION}"
        )

    raw_values = {key: value for key, value in document.items() if key != "version"}
    secret_fields = sorted(set(raw_values) & FORBIDDEN_SECRET_FIELDS)
    if secret_fields:
        raise ConfigurationError(
            "authentication credentials must use environment variables, not "
            f"configuration fields: {', '.join(secret_fields)}"
        )
    unknown_fields = sorted(set(raw_values) - ALLOWED_FIELDS)
    if unknown_fields:
        raise ConfigurationError(
            f"unknown configuration fields: {', '.join(unknown_fields)}"
        )

    values: Dict[str, Any] = {}
    for name, value in raw_values.items():
        values[name] = _validated_value(name, value, path.parent)
    return Configuration(values=values, path=path)


def _validated_value(name: str, value: Any, directory: Path) -> Any:
    if name in BOOLEAN_FIELDS:
        if type(value) is not bool:
            raise ConfigurationError(f"configuration field {name} must be boolean")
        return value
    if name in POSITIVE_INTEGER_FIELDS:
        return _integer(name, value, minimum=1)
    if name in NONNEGATIVE_INTEGER_FIELDS:
        return _integer(name, value, minimum=0)
    if name in POSITIVE_NUMBER_FIELDS:
        return _number(name, value, positive=True)
    if name in NONNEGATIVE_NUMBER_FIELDS:
        return _number(name, value, positive=False)
    if name in STRING_FIELDS:
        if not isinstance(value, str) or not value.strip():
            raise ConfigurationError(
                f"configuration field {name} must be a non-empty string"
            )
        return value.strip()
    if name in PATH_FIELDS:
        if not isinstance(value, str) or not value.strip():
            raise ConfigurationError(
                f"configuration field {name} must be a non-empty path string"
            )
        configured_path = Path(value.strip()).expanduser()
        if not configured_path.is_absolute():
            configured_path = directory / configured_path
        return configured_path
    if name in LIST_FIELDS:
        if not isinstance(value, list) or any(
            not isinstance(item, str) or not item.strip() for item in value
        ):
            raise ConfigurationError(
                f"configuration field {name} must be a list of non-empty strings"
            )
        normalized_items = (item.strip() for item in value)
        return list(dict.fromkeys(normalized_items))
    if name in CHOICE_FIELDS:
        if not isinstance(value, str):
            raise ConfigurationError(f"configuration field {name} must be a string")
        normalized = value.strip().casefold()
        if normalized not in CHOICE_FIELDS[name]:
            choices = ", ".join(sorted(CHOICE_FIELDS[name]))
            raise ConfigurationError(
                f"configuration field {name} must be one of: {choices}"
            )
        return normalized
    raise ConfigurationError(f"unsupported configuration field: {name}")


def _integer(name: str, value: Any, minimum: int) -> int:
    if type(value) is not int or value < minimum:
        qualifier = "positive" if minimum == 1 else "non-negative"
        raise ConfigurationError(
            f"configuration field {name} must be a {qualifier} integer"
        )
    return value


def _number(name: str, value: Any, positive: bool) -> float:
    if type(value) not in {int, float}:
        raise ConfigurationError(f"configuration field {name} must be a number")
    number = float(value)
    valid = number > 0 if positive else number >= 0
    if not math.isfinite(number) or not valid:
        qualifier = "positive" if positive else "non-negative"
        raise ConfigurationError(
            f"configuration field {name} must be a finite {qualifier} number"
        )
    return number
