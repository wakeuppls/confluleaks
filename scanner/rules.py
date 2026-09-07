from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import regex as re
import yaml

from scanner.models import Rule, Severity


DEFAULT_RULES_PATH = Path(__file__).with_name("default_rules.yaml")


class RuleConfigurationError(ValueError):
    pass


def load_rules(path: Path = DEFAULT_RULES_PATH) -> List[Rule]:
    try:
        with path.open(encoding="utf-8") as rules_file:
            document = yaml.safe_load(rules_file)
    except (OSError, yaml.YAMLError) as error:
        raise RuleConfigurationError(f"cannot load rules from {path}: {error}") from error

    raw_rules = document.get("rules") if isinstance(document, dict) else document
    if not isinstance(raw_rules, list) or not raw_rules:
        raise RuleConfigurationError("rules file must contain a non-empty 'rules' list")

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

    try:
        severity = Severity(str(raw_rule["severity"]).lower())
    except ValueError as error:
        raise RuleConfigurationError(
            f"rule {raw_rule['id']} has invalid severity: {raw_rule['severity']}"
        ) from error

    regex = str(raw_rule["regex"])
    try:
        pattern = re.compile(regex)
    except re.error as error:
        raise RuleConfigurationError(
            f"rule {raw_rule['id']} has invalid regex: {error}"
        ) from error

    try:
        confidence = float(raw_rule.get("confidence", 0.8))
    except (TypeError, ValueError) as error:
        raise RuleConfigurationError(
            f"rule {raw_rule['id']} has invalid confidence"
        ) from error
    if not 0 <= confidence <= 1:
        raise RuleConfigurationError(
            f"rule {raw_rule['id']} confidence must be between 0 and 1"
        )

    raw_keywords = raw_rule.get("keywords", [])
    if not isinstance(raw_keywords, list):
        raise RuleConfigurationError(f"rule {raw_rule['id']} keywords must be a list")

    context_radius = _integer_setting(raw_rule, "context_radius", 120)
    if context_radius < 0:
        raise RuleConfigurationError(
            f"rule {raw_rule['id']} context_radius must not be negative"
        )

    min_entropy = _optional_float_setting(raw_rule, "min_entropy")
    if min_entropy is not None and min_entropy < 0:
        raise RuleConfigurationError(
            f"rule {raw_rule['id']} min_entropy must not be negative"
        )

    allowlist_patterns, stopwords = _load_allowlist(raw_rule)

    return Rule(
        id=str(raw_rule["id"]),
        name=str(raw_rule.get("name", raw_rule["id"])),
        severity=severity,
        regex=regex,
        pattern=pattern,
        confidence=confidence,
        keywords=tuple(str(keyword).lower() for keyword in raw_keywords),
        require_context=bool(raw_rule.get("require_context", False)),
        context_radius=context_radius,
        min_entropy=min_entropy,
        allowlist_patterns=allowlist_patterns,
        stopwords=stopwords,
    )


def _integer_setting(raw_rule: Dict[str, Any], name: str, default: int) -> int:
    try:
        return int(raw_rule.get(name, default))
    except (TypeError, ValueError) as error:
        raise RuleConfigurationError(
            f"rule {raw_rule.get('id', '<unknown>')} has invalid {name}"
        ) from error


def _optional_float_setting(
    raw_rule: Dict[str, Any], name: str
) -> Optional[float]:
    value = raw_rule.get(name)
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError) as error:
        raise RuleConfigurationError(
            f"rule {raw_rule.get('id', '<unknown>')} has invalid {name}"
        ) from error


def _load_allowlist(
    raw_rule: Dict[str, Any]
) -> Tuple[Tuple[re.Pattern, ...], Tuple[str, ...]]:
    raw_allowlist = raw_rule.get("allowlist", {})
    if raw_allowlist is None:
        raw_allowlist = {}
    if not isinstance(raw_allowlist, dict):
        raise RuleConfigurationError(
            f"rule {raw_rule['id']} allowlist must be an object"
        )

    raw_regexes = raw_allowlist.get("regexes", [])
    raw_stopwords = raw_allowlist.get("stopwords", [])
    if not isinstance(raw_regexes, list):
        raise RuleConfigurationError(
            f"rule {raw_rule['id']} allowlist.regexes must be a list"
        )
    if not isinstance(raw_stopwords, list):
        raise RuleConfigurationError(
            f"rule {raw_rule['id']} allowlist.stopwords must be a list"
        )

    patterns = []
    for expression in raw_regexes:
        try:
            patterns.append(re.compile(str(expression), re.IGNORECASE))
        except re.error as error:
            raise RuleConfigurationError(
                f"rule {raw_rule['id']} has invalid allowlist regex: {error}"
            ) from error

    return (
        tuple(patterns),
        tuple(str(stopword).lower() for stopword in raw_stopwords),
    )
