import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, Optional

from scanner.models import Finding, ScanResult


BASELINE_VERSION = 1
IDENTITY_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class BaselineError(ValueError):
    """A baseline cannot be read or written safely."""


@dataclass(frozen=True)
class Baseline:
    finding_ids: FrozenSet[str]
    version: int = BASELINE_VERSION


def finding_identity(finding: Finding) -> str:
    """Build an opaque identity stable across page revisions and line moves."""
    material = json.dumps(
        [
            finding.rule_id,
            finding.fingerprint,
            finding.page_id,
            finding.attachment_id or "",
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def load_baseline(path: Path) -> Baseline:
    try:
        with path.open(encoding="utf-8") as stream:
            payload = json.load(stream)
    except OSError as error:
        raise BaselineError(f"cannot read baseline: {path}") from error
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BaselineError(f"baseline is not valid UTF-8 JSON: {path}") from error

    if not isinstance(payload, dict):
        raise BaselineError("baseline root must be an object")
    version = payload.get("version")
    if type(version) is not int or version != BASELINE_VERSION:
        raise BaselineError(
            f"unsupported baseline version: expected {BASELINE_VERSION}"
        )
    entries = payload.get("findings")
    if not isinstance(entries, list):
        raise BaselineError("baseline findings must be a list")

    finding_ids = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise BaselineError(f"baseline finding {index} must be an object")
        identity = entry.get("id")
        if not isinstance(identity, str) or not IDENTITY_PATTERN.fullmatch(identity):
            raise BaselineError(f"baseline finding {index} has an invalid id")
        finding_ids.add(identity)

    return Baseline(finding_ids=frozenset(finding_ids), version=version)


def apply_baseline(result: ScanResult, baseline: Baseline) -> ScanResult:
    remaining = []
    suppressed = 0
    for finding in result.findings:
        if finding_identity(finding) in baseline.finding_ids:
            suppressed += 1
        else:
            remaining.append(finding)
    result.findings = remaining
    result.findings_suppressed += suppressed
    return result


def write_baseline(path: Path, findings: Iterable[Finding]) -> None:
    entries_by_id: Dict[str, Dict[str, Any]] = {}
    for finding in findings:
        identity = finding_identity(finding)
        entry: Dict[str, Any] = {
            "id": identity,
            "rule_id": finding.rule_id,
            "page_id": finding.page_id,
        }
        if finding.attachment_id:
            entry["attachment_id"] = finding.attachment_id
        entries_by_id[identity] = entry

    payload = {
        "version": BASELINE_VERSION,
        "generated_by": "Confluence Secret Scanner",
        "findings": [entries_by_id[key] for key in sorted(entries_by_id)],
    }

    temporary_path: Optional[Path] = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            os.chmod(stream.name, 0o600)
            json.dump(payload, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(str(temporary_path), str(path))
        temporary_path = None
    except OSError as error:
        raise BaselineError(f"cannot write baseline: {path}") from error
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass
