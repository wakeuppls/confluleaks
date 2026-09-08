import json
import logging
import os
import time
from contextlib import contextmanager
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, Iterator, Optional


LOG_MAX_BYTES = 10 * 1024 * 1024
LOG_BACKUP_COUNT = 3
LOG_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
}


class DiagnosticLogError(ValueError):
    """The diagnostic log cannot be configured safely."""


class _UtcFormatter(logging.Formatter):
    converter = time.gmtime


class _PrivateRotatingFileHandler(RotatingFileHandler):
    def _open(self):
        flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        descriptor = os.open(self.baseFilename, flags, 0o600)
        return os.fdopen(
            descriptor,
            self.mode,
            encoding=self.encoding,
            errors=self.errors,
        )


@contextmanager
def diagnostic_logging(
    path: Optional[Path],
    level: str,
) -> Iterator[logging.Logger]:
    logger = logging.getLogger("confluleaks")
    if path is None:
        yield logger
        return

    normalized_level = level.casefold()
    if normalized_level not in LOG_LEVELS:
        raise DiagnosticLogError(f"unsupported diagnostic log level: {level}")

    log_path = Path(path).expanduser()
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handler = _PrivateRotatingFileHandler(
            log_path,
            maxBytes=LOG_MAX_BYTES,
            backupCount=LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
    except OSError as error:
        raise DiagnosticLogError(
            f"cannot open diagnostic log file: {log_path}"
        ) from error

    formatter = _UtcFormatter(
        "%(asctime)sZ %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    handler.setFormatter(formatter)
    previous_level = logger.level
    previous_propagate = logger.propagate
    logger.addHandler(handler)
    logger.setLevel(LOG_LEVELS[normalized_level])
    logger.propagate = False
    try:
        log_event(
            logger,
            logging.INFO,
            "diagnostic_log.started",
            path=str(log_path),
            log_level=normalized_level,
            max_bytes=LOG_MAX_BYTES,
            backups=LOG_BACKUP_COUNT,
        )
        yield logger
    finally:
        log_event(logger, logging.INFO, "diagnostic_log.stopped")
        logger.removeHandler(handler)
        handler.close()
        logger.setLevel(previous_level)
        logger.propagate = previous_propagate


def log_event(
    logger: logging.Logger,
    level: int,
    event: str,
    **fields: Any,
) -> None:
    payload: Dict[str, Any] = {"event": event}
    payload.update(fields)
    logger.log(
        level,
        json.dumps(payload, ensure_ascii=True, sort_keys=True, default=str),
    )


logging.getLogger("confluleaks").addHandler(logging.NullHandler())
