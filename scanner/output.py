import os
import sys
import tempfile
from pathlib import Path
from typing import Callable, Optional, TextIO


class ReportOutputError(RuntimeError):
    """A report could not be written completely and atomically."""


def write_report_output(
    path: Optional[Path],
    writer: Callable[[TextIO], None],
    stdout: Optional[TextIO] = None,
) -> None:
    """Write to stdout or atomically replace a private report file."""
    if path is None:
        try:
            writer(stdout if stdout is not None else sys.stdout)
        except OSError as error:
            raise ReportOutputError("cannot write report to stdout") from error
        return

    destination = path.expanduser()
    temporary_path: Optional[Path] = None
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=str(destination.parent),
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            os.chmod(stream.name, 0o600)
            writer(stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(str(temporary_path), str(destination))
        temporary_path = None
    except OSError as error:
        raise ReportOutputError(f"cannot write report: {destination}") from error
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass
