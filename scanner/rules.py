import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import regex as re
import yaml

from scanner.models import Rule, Severity


DEFAULT_RULES_PATH = Path(__file__).with_name("default_rules.yaml")
RULE_FIELDS = frozenset(
    {
        "id",
        "name",
        "severity",
        "regex",
        "confidence",
        "keywords",
        "require_context",
        "context_radius",
        "min_entropy",
        "allowlist",
    }
)
ALLOWLIST_FIELDS = frozenset({"regexes", "stopwords"})


class RuleConfigurationError(ValueError):
    pass


def load_rules(path: Path = DEFAULT_RULES_PATH) -> List[Rule]:
    try:
        with path.open(encoding="utf-8") as rules_file:
            document = yaml.safe_load(rules_file)
    except (OSError, yaml.YAMLError) as error:
        raise RuleConfigurationError(
            f"cannot load rules from {path}: {error}"
        ) from error

    raw_rules = document.get("rules") if isinstance(document, dict) else document
    if not isinstance(raw_rules, list) or not raw_rules:
        raise RuleConfigurationError(
            "rules file must contain a non-empty 'rules' list"
        )

    rules = []
    seen_ids = set()
    for index, raw_rule in enumerate(raw_rules, start=1):
        if not isinstance(raw_rule, dict):
            raise RuleConfigurationError(f"rule #{index} must be an object")
        rule = _build_rule(raw_rule, index)
        if rule.id in seen_ids:
            raise RuleConfigurationError(f"duplicate rule id: {rule.id}")
        seen_ids.add(rule.id)
        rules.append(rule)
    return rules


def _build_rule(raw_rule: Dict[str, Any], index: int) -> Rule:
    missing = [key for key in ("id", "severity", "regex") if not raw_rule.get(key)]
    if missing:
        raise RuleConfigurationError(
            f"rule #{index} is missing required fields: {', '.join(missing)}"
        )

    rule_id = _nonempty_string(raw_rule["id"], f"rule #{index} id")
    unknown_fields = sorted(set(raw_rule) - RULE_FIELDS)
    if unknown_fields:
        raise RuleConfigurationError(
            f"rule {rule_id} has unknown fields: {', '.join(unknown_fields)}"
        )

    try:
        severity_value = _nonempty_string(
            raw_rule["severity"],
            f"rule {rule_id} severity",
        )
        severity = Severity(severity_value.casefold())
    except ValueError as error:
        raise RuleConfigurationError(
            f"rule {rule_id} has invalid severity: {raw_rule['severity']}"
        ) from error

    regex = _nonempty_string(raw_rule["regex"], f"rule {rule_id} regex")
    try:
        pattern = re.compile(regex)
    except re.error as error:
        raise RuleConfigurationError(
            f"rule {rule_id} has invalid regex: {error}"
        ) from error
    if pattern.search("") is not None:
        raise RuleConfigurationError(f"rule {rule_id} regex must not match empty text")

    confidence = _number_setting(raw_rule, "confidence", 0.8, rule_id)
    if not 0 <= confidence <= 1:
        raise RuleConfigurationError(
            f"rule {rule_id} confidence must be between 0 and 1"
        )

    raw_keywords = raw_rule.get("keywords", [])
    if not isinstance(raw_keywords, list):
        raise RuleConfigurationError(f"rule {rule_id} keywords must be a list")
    keywords = _string_list(raw_keywords, f"rule {rule_id} keywords")

    require_context = raw_rule.get("require_context", False)
    if type(require_context) is not bool:
        raise RuleConfigurationError(
            f"rule {rule_id} require_context must be boolean"
        )
    if require_context and not keywords:
        raise RuleConfigurationError(
            f"rule {rule_id} require_context needs at least one keyword"
        )

    context_radius = _integer_setting(raw_rule, "context_radius", 120, rule_id)
    if context_radius < 0:
        raise RuleConfigurationError(
            f"rule {rule_id} context_radius must not be negative"
        )

    min_entropy = _optional_number_setting(raw_rule, "min_entropy", rule_id)
    if min_entropy is not None and min_entropy < 0:
        raise RuleConfigurationError(
            f"rule {rule_id} min_entropy must not be negative"
        )

    allowlist_patterns, stopwords = _load_allowlist(raw_rule, rule_id)
    name = _nonempty_string(raw_rule.get("name", rule_id), f"rule {rule_id} name")

    return Rule(
        id=rule_id,
        name=name,
        severity=severity,
        regex=regex,
        pattern=pattern,
        confidence=confidence,
        keywords=tuple(keyword.casefold() for keyword in keywords),
        require_context=require_context,
        context_radius=context_radius,
        min_entropy=min_entropy,
        allowlist_patterns=allowlist_patterns,
        stopwords=stopwords,
    )


def _integer_setting(
    raw_rule: Dict[str, Any],
    name: str,
    default: int,
    rule_id: str,
) -> int:
    value = raw_rule.get(name, default)
    if type(value) is not int:
        raise RuleConfigurationError(
            f"rule {rule_id} {name} must be an integer"
        )
    return value


def _optional_number_setting(
    raw_rule: Dict[str, Any],
    name: str,
    rule_id: str,
) -> Optional[float]:
    value = raw_rule.get(name)
    if value is None:
        return None
    return _number(value, f"rule {rule_id} {name}")


def _number_setting(
    raw_rule: Dict[str, Any],
    name: str,
    default: float,
    rule_id: str,
) -> float:
    return _number(raw_rule.get(name, default), f"rule {rule_id} {name}")


def _number(value: Any, label: str) -> float:
    if type(value) not in {int, float}:
        raise RuleConfigurationError(f"{label} must be a number")
    number = float(value)
    if not math.isfinite(number):
        raise RuleConfigurationError(f"{label} must be finite")
    return number


def _nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RuleConfigurationError(f"{label} must be a non-empty string")
    return value.strip()


def _string_list(values: List[Any], label: str) -> Tuple[str, ...]:
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise RuleConfigurationError(
            f"{label} must contain only non-empty strings"
        )
    return tuple(value.strip() for value in values)


def _load_allowlist(
    raw_rule: Dict[str, Any],
    rule_id: str,
) -> Tuple[Tuple[re.Pattern, ...], Tuple[str, ...]]:
    raw_allowlist = raw_rule.get("allowlist", {})
    if raw_allowlist is None:
        raw_allowlist = {}
    if not isinstance(raw_allowlist, dict):
        raise RuleConfigurationError(
            f"rule {rule_id} allowlist must be an object"
        )

    unknown_fields = sorted(set(raw_allowlist) - ALLOWLIST_FIELDS)
    if unknown_fields:
        raise RuleConfigurationError(
            f"rule {rule_id} allowlist has unknown fields: "
            f"{', '.join(unknown_fields)}"
        )

    raw_regexes = raw_allowlist.get("regexes", [])
    raw_stopwords = raw_allowlist.get("stopwords", [])
    if not isinstance(raw_regexes, list):
        raise RuleConfigurationError(
            f"rule {rule_id} allowlist.regexes must be a list"
        )
    if not isinstance(raw_stopwords, list):
        raise RuleConfigurationError(
            f"rule {rule_id} allowlist.stopwords must be a list"
        )
    regexes = _string_list(raw_regexes, f"rule {rule_id} allowlist.regexes")
    stopwords = _string_list(raw_stopwords, f"rule {rule_id} allowlist.stopwords")

    patterns = []
    for expression in regexes:
        try:
            pattern = re.compile(expression, re.IGNORECASE)
        except re.error as error:
            raise RuleConfigurationError(
                f"rule {rule_id} has invalid allowlist regex: {error}"
            ) from error
        if pattern.search("") is not None:
            raise RuleConfigurationError(
                f"rule {rule_id} allowlist regex must not match empty text"
            )
        patterns.append(pattern)

    return (
        tuple(patterns),
        tuple(stopword.casefold() for stopword in stopwords),
    )
